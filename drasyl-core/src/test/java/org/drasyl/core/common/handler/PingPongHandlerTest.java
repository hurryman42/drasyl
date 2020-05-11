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
package org.drasyl.core.common.handler;

import org.drasyl.core.common.message.NodeServerExceptionMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.drasyl.core.common.message.LeaveMessage;
import org.drasyl.core.common.message.PingMessage;
import org.drasyl.core.common.message.PongMessage;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.never;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;

import java.util.concurrent.atomic.AtomicInteger;

class PingPongHandlerTest {
    private ChannelHandlerContext ctx;
    private IdleStateEvent evt;

    @BeforeEach
    void setUp() throws Exception {
        ctx = mock(ChannelHandlerContext.class);
        evt = mock(IdleStateEvent.class);
        when(evt.state()).thenReturn(IdleState.READER_IDLE);
    }

    @Test
    void userEventTriggeredShouldSendPingMessageIfThresholdNotReached() throws Exception {
        PingPongHandler handler = new PingPongHandler((short) 1, new AtomicInteger(0));
        handler.userEventTriggered(ctx, evt);

        verify(ctx).writeAndFlush(any(PingMessage.class));
    }

    @Test
    void userEventTriggeredShouldSendExceptionMessageIfThresholdIsReached() throws Exception {
        PingPongHandler handler = new PingPongHandler((short) 1, new AtomicInteger(2));
        handler.userEventTriggered(ctx, evt);

        verify(ctx).writeAndFlush(any(NodeServerExceptionMessage.class));
    }

    @Test
    void userEventTriggeredShouldSendCorrectNumberOfPingMessages() throws Exception {
        PingPongHandler handler = new PingPongHandler((short) 2, new AtomicInteger(0));

        for (int i = 0; i < 3; i++) {
            handler.userEventTriggered(ctx, evt);
        }

        assertEquals(3, handler.counter.get());
        verify(ctx, times(3)).writeAndFlush(any(PingMessage.class));
    }

    @Test
    void userEventTriggeredShouldIgnoreUnrelatedEvents() throws Exception {
        when(evt.state()).thenReturn(IdleState.WRITER_IDLE);
        PingPongHandler handler = new PingPongHandler((short) 1, new AtomicInteger(0));
        handler.userEventTriggered(ctx, evt);

        verify(ctx, never()).writeAndFlush(any());
    }

    @Test
    void channelRead0ShouldReplyWithPongMessageToPingMessage() throws Exception {
        PingPongHandler handler = new PingPongHandler((short) 1, new AtomicInteger(0));
        handler.channelRead0(ctx, new PingMessage());

        verify(ctx).writeAndFlush(any(PongMessage.class));
    }

    @Test
    void channelRead0ShouldResetCounterIfPingMessageReceived() throws Exception {
        PingPongHandler handler = new PingPongHandler((short) 1, new AtomicInteger(0));
        handler.channelRead0(ctx, new PongMessage());

        assertEquals(0, handler.counter.get());
    }

    @Test
    void channelRead0ShouldPassThroughAllUnrelatedMessages() throws Exception {
        PingPongHandler handler = new PingPongHandler((short) 1, new AtomicInteger(0));
        handler.channelRead0(ctx, new LeaveMessage());

        assertEquals(0, handler.counter.get());
        verify(ctx).fireChannelRead(any(LeaveMessage.class));
    }
}
