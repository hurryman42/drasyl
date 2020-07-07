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
import org.drasyl.peer.connection.message.ApplicationMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.concurrent.CompletableFuture;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class DuplexHandlerTest {
    @Mock
    private HandlerContext ctx;

    @Test
    void shouldPassthroughsOnWrite() {
        DuplexHandler duplexHandler = new DuplexHandler();

        ApplicationMessage msg = mock(ApplicationMessage.class);
        CompletableFuture<Void> future = mock(CompletableFuture.class);

        duplexHandler.write(ctx, msg, future);

        verify(ctx).write(eq(msg), eq(future));
    }

    @Test
    void shouldPassthroughsOnRead() {
        DuplexHandler duplexHandler = new DuplexHandler();

        ApplicationMessage msg = mock(ApplicationMessage.class);

        duplexHandler.read(ctx, msg);

        verify(ctx).fireRead(eq(msg));
    }

    @Test
    void shouldPassthroughsOnEventTriggered() {
        DuplexHandler duplexHandler = new DuplexHandler();

        Event event = mock(Event.class);

        duplexHandler.eventTriggered(ctx, event);

        verify(ctx).fireEventTriggered(eq(event));
    }

    @Test
    void shouldPassthroughsOnExceptionCaught() {
        DuplexHandler duplexHandler = new DuplexHandler();

        Exception exception = mock(Exception.class);

        duplexHandler.exceptionCaught(ctx, exception);

        verify(ctx).fireExceptionCaught(eq(exception));
    }
}