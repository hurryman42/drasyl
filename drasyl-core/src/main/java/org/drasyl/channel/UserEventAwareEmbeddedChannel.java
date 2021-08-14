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
package org.drasyl.channel;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.ReferenceCountUtil;
import org.drasyl.util.ArrayUtil;

import java.util.ArrayDeque;
import java.util.Queue;

/**
 * A {@link EmbeddedChannel} that record all received user events.
 */
public class UserEventAwareEmbeddedChannel extends EmbeddedChannel {
    public UserEventAwareEmbeddedChannel(final ChannelHandler... handlers) {
        super(ArrayUtil.concat(handlers, new ChannelHandler[]{ new UserEventAcceptor() }));
    }

    /**
     * Returns the {@link Queue} which holds all the user events that were received by this {@link
     * Channel}.
     */
    @SuppressWarnings("java:S2384")
    public Queue<Object> userEvents() {
        return pipeline().get(UserEventAcceptor.class).userEvents();
    }

    /**
     * Return received user events from this {@link Channel}
     */
    @SuppressWarnings("unchecked")
    public <T> T readUserEvent() {
        final T event = (T) poll(pipeline().get(UserEventAcceptor.class).userEvents());
        if (event != null) {
            ReferenceCountUtil.touch(event, "Caller of readInbound() will handle the user event from this point");
        }
        return event;
    }

    private static Object poll(final Queue<Object> queue) {
        return queue != null ? queue.poll() : null;
    }

    private static class UserEventAcceptor extends ChannelInboundHandlerAdapter {
        private Queue<Object> userEvents;

        @Override
        public void userEventTriggered(final ChannelHandlerContext ctx,
                                       final Object evt) {
            userEvents().add(evt);
        }

        public Queue<Object> userEvents() {
            if (userEvents == null) {
                userEvents = new ArrayDeque<>();
            }
            return userEvents;
        }
    }
}
