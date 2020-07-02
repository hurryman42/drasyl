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

import org.drasyl.event.Event;
import org.drasyl.event.MessageEvent;
import org.drasyl.peer.connection.message.ApplicationMessage;
import org.drasyl.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

final class TailContext extends AbstractHandlerContext implements InboundHandler, OutboundHandler {
    private static final Logger LOG = LoggerFactory.getLogger(TailContext.class);
    public static final String DRASYL_TAIL_HANDLER = "DRASYL_TAIL_HANDLER";
    private final Consumer<Event> eventConsumer;

    public TailContext(Consumer<Event> eventConsumer) {
        super(DRASYL_TAIL_HANDLER);
        this.eventConsumer = eventConsumer;
    }

    @Override
    public Handler handler() {
        return this;
    }

    @Override
    public void read(HandlerContext ctx, ApplicationMessage msg) {
        // Pass message to Application
        eventConsumer.accept(new MessageEvent(Pair.of(msg.getSender(), msg.getPayload())));
    }

    @Override
    public void eventTriggered(HandlerContext ctx, Event event) {
        // Pass event to Application
        eventConsumer.accept(event);
    }

    @Override
    public void exceptionCaught(HandlerContext ctx, Exception cause) throws Exception {
        throw new PipelineException(cause);
    }

    @Override
    public void write(HandlerContext ctx,
                      ApplicationMessage msg,
                      CompletableFuture<Void> future) {
        ctx.write(msg, future);
    }

    @Override
    public void handlerAdded(HandlerContext ctx) throws Exception {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Pipeline tail was added.");
        }
    }

    @Override
    public void handlerRemoved(HandlerContext ctx) throws Exception {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Pipeline tail was removed.");
        }
    }
}
