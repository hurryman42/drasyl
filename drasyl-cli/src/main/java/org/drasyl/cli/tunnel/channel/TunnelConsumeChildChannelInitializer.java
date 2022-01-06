/*
 * Copyright (c) 2020-2021 Heiko Bornholdt and Kevin Röbert
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 */
package org.drasyl.cli.tunnel.channel;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.timeout.WriteTimeoutHandler;
import org.drasyl.channel.DrasylChannel;
import org.drasyl.cli.handler.PrintAndExitOnExceptionHandler;
import org.drasyl.cli.tunnel.handler.ConsumeDrasylHandler;
import org.drasyl.cli.tunnel.handler.TunnelWriteCodec;
import org.drasyl.cli.tunnel.message.JacksonCodecTunnelMessage;
import org.drasyl.handler.arq.gobackn.ByteToGoBackNArqDataCodec;
import org.drasyl.handler.arq.gobackn.GoBackNArqCodec;
import org.drasyl.handler.arq.gobackn.GoBackNArqHandler;
import org.drasyl.handler.codec.JacksonCodec;
import org.drasyl.identity.Identity;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.node.handler.crypto.ArmHeaderCodec;
import org.drasyl.node.handler.crypto.LongTimeArmHandler;
import org.drasyl.util.Worm;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import java.io.PrintStream;
import java.time.Duration;

import static java.util.Objects.requireNonNull;
import static org.drasyl.cli.tunnel.TunnelExposeCommand.WRITE_TIMEOUT_SECONDS;
import static org.drasyl.cli.tunnel.channel.TunnelExposeChannelInitializer.MAX_PEERS;
import static org.drasyl.cli.tunnel.channel.TunnelExposeChildChannelInitializer.ARM_SESSION_TIME;
import static org.drasyl.cli.tunnel.channel.TunnelExposeChildChannelInitializer.ARQ_RETRY_TIMEOUT;
import static org.drasyl.cli.wormhole.channel.WormholeSendChildChannelInitializer.ARQ_WINDOW_SIZE;
import static org.drasyl.util.Preconditions.requireNonNegative;

public class TunnelConsumeChildChannelInitializer extends ChannelInitializer<DrasylChannel> {
    private static final Logger LOG = LoggerFactory.getLogger(TunnelConsumeChildChannelInitializer.class);
    private final PrintStream out;
    private final PrintStream err;
    private final Worm<Integer> exitCode;
    private final Identity identity;
    private final IdentityPublicKey exposer;
    private final String password;
    private final int port;

    public TunnelConsumeChildChannelInitializer(final PrintStream out,
                                                final PrintStream err,
                                                final Worm<Integer> exitCode,
                                                final Identity identity,
                                                final IdentityPublicKey exposer,
                                                final String password,
                                                final int port) {
        this.out = requireNonNull(out);
        this.err = requireNonNull(err);
        this.exitCode = requireNonNull(exitCode);
        this.identity = requireNonNull(identity);
        this.exposer = requireNonNull(exposer);
        this.password = requireNonNull(password);
        this.port = requireNonNegative(port);
    }

    @Override
    protected void initChannel(final DrasylChannel ch) throws Exception {
        if (!exposer.equals(ch.remoteAddress())) {
            LOG.trace("Close channel for peer `{}` that is not the service exposer.", ch.remoteAddress());
            ch.close();
            return;
        }

        final ChannelPipeline p = ch.pipeline();

        p.addLast(new ArmHeaderCodec());
        p.addLast(new LongTimeArmHandler(ARM_SESSION_TIME, MAX_PEERS, identity, (IdentityPublicKey) ch.remoteAddress()));

        // add ARQ to make sure messages arrive
        p.addLast(new GoBackNArqCodec());
        p.addLast(new GoBackNArqHandler(ARQ_WINDOW_SIZE, Duration.ofMillis(ARQ_RETRY_TIMEOUT), Duration.ofMillis(50)));
        p.addLast(new ByteToGoBackNArqDataCodec());
        p.addLast(new WriteTimeoutHandler(WRITE_TIMEOUT_SECONDS));

        // (de)serializers for TunnelMessages
        p.addLast(new TunnelWriteCodec());
        p.addLast(new JacksonCodec<>(JacksonCodecTunnelMessage.class));

        p.addLast(new ConsumeDrasylHandler(out, port, exposer, password));

        p.addLast(new PrintAndExitOnExceptionHandler(err, exitCode));

        // close parent as well
        ch.closeFuture().addListener(f -> ch.parent().close());
    }
}
