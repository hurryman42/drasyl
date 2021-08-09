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
package org.drasyl.remote.handler;

import com.typesafe.config.Config;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import org.drasyl.channel.MigrationInboundMessage;
import org.drasyl.channel.MigrationOutboundMessage;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.pipeline.Stateless;
import org.drasyl.pipeline.address.Address;
import org.drasyl.pipeline.address.InetSocketAddressWrapper;
import org.drasyl.pipeline.skeleton.SimpleDuplexHandler;
import org.drasyl.remote.protocol.ApplicationMessage;
import org.drasyl.util.FutureCombiner;
import org.drasyl.util.FutureUtil;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import java.util.concurrent.CompletableFuture;

import static org.drasyl.channel.DefaultDrasylServerChannel.CONFIG_ATTR_KEY;
import static org.drasyl.channel.DefaultDrasylServerChannel.PEERS_MANAGER_ATTR_KEY;

/**
 * This handler uses preconfigured static routes ({@link org.drasyl.DrasylConfig#getStaticRoutes(Config,
 * String)}) to deliver messages.
 */
@ChannelHandler.Sharable
@Stateless
public final class StaticRoutesHandler extends SimpleDuplexHandler<Object, ApplicationMessage, IdentityPublicKey> {
    public static final StaticRoutesHandler INSTANCE = new StaticRoutesHandler();
    private static final Logger LOG = LoggerFactory.getLogger(StaticRoutesHandler.class);
    private static final Object path = StaticRoutesHandler.class;

    private StaticRoutesHandler() {
        // singleton
    }

    @Override
    protected void matchedOutbound(final ChannelHandlerContext ctx,
                                   final IdentityPublicKey recipient,
                                   final ApplicationMessage envelope,
                                   final CompletableFuture<Void> future) {
        final InetSocketAddressWrapper staticAddress = ctx.attr(CONFIG_ATTR_KEY).get().getRemoteStaticRoutes().get(recipient);
        if (staticAddress != null) {
            LOG.trace("Send message `{}` via static route {}.", () -> envelope, () -> staticAddress);
            FutureCombiner.getInstance().add(FutureUtil.toFuture(ctx.writeAndFlush(new MigrationOutboundMessage<>((Object) envelope, (Address) staticAddress)))).combine(future);
        }
        else {
            // passthrough message
            FutureCombiner.getInstance().add(FutureUtil.toFuture(ctx.writeAndFlush(new MigrationOutboundMessage<>((Object) envelope, (Address) recipient)))).combine(future);
        }
    }

    @Override
    protected void matchedInbound(final ChannelHandlerContext ctx,
                                  final IdentityPublicKey sender,
                                  final Object msg) throws Exception {
        ctx.fireChannelRead(new MigrationInboundMessage<>(msg, sender));
    }

    @Override
    public void channelActive(final ChannelHandlerContext ctx) throws Exception {
        populateRoutes(ctx);

        super.channelActive(ctx);
    }

    @Override
    public void channelInactive(final ChannelHandlerContext ctx) throws Exception {
        clearRoutes(ctx);

        super.channelInactive(ctx);
    }

    private static synchronized void populateRoutes(final ChannelHandlerContext ctx) {
        ctx.attr(CONFIG_ATTR_KEY).get().getRemoteStaticRoutes().forEach(((publicKey, address) -> ctx.attr(PEERS_MANAGER_ATTR_KEY).get().addPath(ctx, publicKey, path)));
    }

    private static synchronized void clearRoutes(final ChannelHandlerContext ctx) {
        ctx.attr(CONFIG_ATTR_KEY).get().getRemoteStaticRoutes().keySet().forEach(publicKey -> ctx.attr(PEERS_MANAGER_ATTR_KEY).get().removePath(ctx, publicKey, path));
    }
}
