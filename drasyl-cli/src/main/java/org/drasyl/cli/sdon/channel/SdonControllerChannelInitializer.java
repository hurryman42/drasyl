/*
 * Copyright (c) 2020-2023 Heiko Bornholdt and Kevin Röbert
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
package org.drasyl.cli.sdon.channel;

import io.netty.channel.ChannelPipeline;
import org.drasyl.channel.DrasylServerChannel;
import org.drasyl.cli.channel.AbstractChannelInitializer;
import org.drasyl.cli.handler.PrintAndExitOnExceptionHandler;
import org.drasyl.cli.sdon.config.Network;
import org.drasyl.cli.sdon.handler.SdonControllerHandler;
import org.drasyl.util.Worm;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;
import org.drasyl.util.network.Subnet;

import java.io.PrintStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import static java.util.Objects.requireNonNull;

@SuppressWarnings("java:S110")
public class SdonControllerChannelInitializer extends AbstractChannelInitializer {
    private static final Logger LOG = LoggerFactory.getLogger(SdonControllerChannelInitializer.class);
    private final PrintStream out;
    private final PrintStream err;
    private final Worm<Integer> exitCode;
    private final Network network;
    private java.security.PublicKey publicKey;
    private PrivateKey privateKey;
    private List<String> certificates;
    private X509Certificate myCert;
    private Subnet mySubnet;

    @SuppressWarnings("java:S107")
    public SdonControllerChannelInitializer(final long onlineTimeoutMillis,
                                            final PrintStream out,
                                            final PrintStream err,
                                            final Worm<Integer> exitCode,
                                            final Network network,
                                            final java.security.PublicKey publicKey,
                                            final PrivateKey privateKey,
                                            final List<String> certificates,
                                            final X509Certificate myCert,
                                            final Subnet mySubnet) {
        super(onlineTimeoutMillis);
        this.out = requireNonNull(out);
        this.err = requireNonNull(err);
        this.exitCode = requireNonNull(exitCode);
        this.network = requireNonNull(network);
        this.publicKey = requireNonNull(publicKey);
        this.privateKey = requireNonNull(privateKey);
        this.certificates = requireNonNull(certificates);
        this.myCert = requireNonNull(myCert);
        this.mySubnet = requireNonNull(mySubnet);
    }

    @Override
    protected void initChannel(final DrasylServerChannel ch) {
        super.initChannel(ch);

        final ChannelPipeline p = ch.pipeline();
        p.addLast(new SdonControllerHandler(out, network, publicKey, privateKey, certificates, myCert, mySubnet));
        p.addLast(new PrintAndExitOnExceptionHandler(err, exitCode));
    }
}
