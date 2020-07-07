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
package org.drasyl.pipeline;

import io.netty.util.internal.TypeParameterMatcher;
import org.drasyl.peer.connection.message.ApplicationMessage;
import org.drasyl.peer.connection.message.ChunkedMessage;

import java.util.concurrent.CompletableFuture;

/**
 * {@link OutboundHandlerAdapter} which allows to explicit only handle a specific type of messages.
 * <p>
 * For example here is an implementation which only handle {@link ChunkedMessage}s.
 *
 * <pre>
 *     public class ChunkedHandler extends
 *             {@link SimpleOutboundHandler}&lt;{@link ChunkedMessage}&gt; {
 *
 *         {@code @Override}
 *         protected void matchedWrite({@link HandlerContext} ctx, {@link ChunkedMessage} msg, {@link CompletableFuture}&lt;{@link Void}&gt future) {
 *             System.out.println(msg);
 *         }
 *     }
 * </pre>
 */
public abstract class SimpleOutboundHandler<O> extends OutboundHandlerAdapter {
    private final TypeParameterMatcher matcherMessage;

    /**
     * Create a new instance which will try to detect the types to match out of the type parameter
     * of the class.
     */
    protected SimpleOutboundHandler() {
        matcherMessage = TypeParameterMatcher.find(this, SimpleOutboundHandler.class, "O");
    }

    /**
     * Create a new instance
     *
     * @param outboundMessageType the type of messages to match
     */
    protected SimpleOutboundHandler(Class<? extends O> outboundMessageType) {
        matcherMessage = TypeParameterMatcher.get(outboundMessageType);
    }

    @Override
    public void write(HandlerContext ctx,
                      ApplicationMessage msg,
                      CompletableFuture<Void> future) {
        if (acceptOutbound(msg)) {
            @SuppressWarnings("unchecked")
            O castedMsg = (O) msg;
            matchedWrite(ctx, castedMsg, future);
        }
        else {
            ctx.write(msg, future);
        }
    }

    /**
     * Returns {@code true} if the given message should be handled. If {@code false} it will be
     * passed to the next {@link InboundHandler} in the {@link Pipeline}.
     */
    protected boolean acceptOutbound(ApplicationMessage msg) {
        return matcherMessage.match(msg);
    }

    /**
     * Is called for each message of type {@link O}.
     *
     * @param ctx    handler context
     * @param msg    the message
     * @param future a future for the message
     */
    protected abstract void matchedWrite(HandlerContext ctx,
                                         O msg,
                                         CompletableFuture<Void> future);
}
