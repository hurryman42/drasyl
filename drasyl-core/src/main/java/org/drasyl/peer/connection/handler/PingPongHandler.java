/*
 * Copyright (c) 2020.
 *
 * This file is part of drasyl.
 *
 *  drasyl is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  drasyl is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with drasyl.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.drasyl.peer.connection.handler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import org.drasyl.identity.CompressedPublicKey;
import org.drasyl.identity.Identity;
import org.drasyl.peer.connection.message.Message;
import org.drasyl.peer.connection.message.PingMessage;
import org.drasyl.peer.connection.message.PongMessage;

import java.util.concurrent.atomic.AtomicInteger;

import static org.drasyl.peer.connection.handler.ThreeWayHandshakeClientHandler.ATTRIBUTE_PUBLIC_KEY;

/**
 * This handler acts as a health check for a connection. It periodically sends {@link PingMessage}s,
 * which must be answered with a {@link PongMessage}. When a configured threshold of messages is not
 * answered, the connection is considered unhealthy and is closed.
 */
public class PingPongHandler extends SimpleChannelInboundHandler<Message> {
    public static final String PING_PONG_HANDLER = "pingPongHandler";
    private final int networkId;
    private final Identity identity;
    protected final short maxRetries;
    protected final AtomicInteger retries;

    /**
     * PingPongHandler with {@code retries} retries, until channel is closed.
     */
    public PingPongHandler(final int networkId,
                           final Identity identity,
                           final short maxRetries) {
        this(networkId, identity, maxRetries, new AtomicInteger(0));
    }

    PingPongHandler(final int networkId,
                    final Identity identity,
                    final short maxRetries,
                    final AtomicInteger retries) {
        this.networkId = networkId;
        this.identity = identity;
        this.maxRetries = maxRetries;
        this.retries = retries;
    }

    @Override
    public void userEventTriggered(final ChannelHandlerContext ctx,
                                   final Object evt) throws Exception {
        super.userEventTriggered(ctx, evt);

        // only send pings if channel is idle
        if (evt instanceof IdleStateEvent) {
            final IdleStateEvent e = (IdleStateEvent) evt;
            if (e.state() == IdleState.READER_IDLE) {
                if (retries.getAndIncrement() > maxRetries) {
                    // threshold reached, close connection
                    ctx.close();
                }
                else if (ctx.channel().hasAttr(ATTRIBUTE_PUBLIC_KEY)) {
                    final CompressedPublicKey publicKey = ctx.channel().attr(ATTRIBUTE_PUBLIC_KEY).get();

                    // send (next) ping
                    ctx.writeAndFlush(new PingMessage(networkId, identity.getPublicKey(), identity.getProofOfWork(), publicKey));
                }
            }
        }
    }

    @Override
    protected void channelRead0(final ChannelHandlerContext ctx, final Message msg) {
        if (msg instanceof PingMessage) {
            // reply to received ping with pong message
            ctx.writeAndFlush(new PongMessage(networkId, identity.getPublicKey(), identity.getProofOfWork(), msg.getSender(), msg.getId()));
        }
        else if (msg instanceof PongMessage) {
            // pong received, reset retries counter
            retries.set(0);
        }
        else {
            // passthroughs all other messages
            ctx.fireChannelRead(msg);
        }
    }
}