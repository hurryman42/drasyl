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

import io.reactivex.rxjava3.core.Scheduler;
import org.drasyl.DrasylConfig;
import org.drasyl.DrasylException;
import org.drasyl.event.Event;
import org.drasyl.identity.CompressedPublicKey;
import org.drasyl.identity.Identity;
import org.drasyl.peer.connection.message.ApplicationMessage;
import org.drasyl.pipeline.codec.ObjectHolder;
import org.drasyl.pipeline.codec.TypeValidator;
import org.drasyl.util.DrasylConsumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class HeadContextTest {
    @Mock
    private DrasylConsumer<ApplicationMessage, DrasylException> outboundConsumer;
    @Mock
    private HandlerContext ctx;
    @Mock
    private DrasylConfig config;
    @Mock
    private Pipeline pipeline;
    @Mock
    private Scheduler scheduler;
    @Mock
    private Identity identity;
    @Mock
    private TypeValidator validator;

    @Test
    void shouldReturnSelfAsHandler() {
        HeadContext headContext = new HeadContext(outboundConsumer, config, pipeline, scheduler, () -> identity, validator);

        assertEquals(headContext, headContext.handler());
    }

    @Test
    void shouldDoNothingOnHandlerAdded() {
        HeadContext headContext = new HeadContext(outboundConsumer, config, pipeline, scheduler, () -> identity, validator);

        headContext.handlerAdded(ctx);

        verifyNoInteractions(ctx);
    }

    @Test
    void shouldDoNothingOnHandlerRemoved() {
        HeadContext headContext = new HeadContext(outboundConsumer, config, pipeline, scheduler, () -> identity, validator);

        headContext.handlerRemoved(ctx);

        verifyNoInteractions(ctx);
    }

    @Test
    void shouldPassthroughsOnRead() {
        HeadContext headContext = new HeadContext(outboundConsumer, config, pipeline, scheduler, () -> identity, validator);
        CompressedPublicKey sender = mock(CompressedPublicKey.class);
        Object msg = mock(Object.class);

        headContext.read(ctx, sender, msg);

        verify(ctx).fireRead(eq(sender), eq(msg));
    }

    @Test
    void shouldPassthroughsOnEvent() {
        HeadContext headContext = new HeadContext(outboundConsumer, config, pipeline, scheduler, () -> identity, validator);
        Event event = mock(Event.class);

        headContext.eventTriggered(ctx, event);

        verify(ctx).fireEventTriggered(eq(event));
    }

    @Test
    void shouldPassthroughsOnException() throws Exception {
        HeadContext headContext = new HeadContext(outboundConsumer, config, pipeline, scheduler, () -> identity, validator);
        Exception exception = mock(Exception.class);

        headContext.exceptionCaught(ctx, exception);

        verify(ctx).fireExceptionCaught(eq(exception));
    }

    @Test
    void shouldWriteToConsumer() throws Exception {
        HeadContext headContext = new HeadContext(outboundConsumer, config, pipeline, scheduler, () -> identity, validator);
        CompressedPublicKey sender = mock(CompressedPublicKey.class);
        CompressedPublicKey recipient = mock(CompressedPublicKey.class);
        when(identity.getPublicKey()).thenReturn(sender);
        ObjectHolder msg = ObjectHolder.of(byte[].class, new byte[]{});
        CompletableFuture<Void> future = mock(CompletableFuture.class);

        when(future.isDone()).thenReturn(false);

        headContext.write(ctx, recipient, msg, future);

        verify(outboundConsumer).accept(eq(new ApplicationMessage(sender, recipient, msg.getObject(), msg.getClazz())));
        verify(future).complete(null);
    }

    @Test
    void shouldNotWriteToConsumerIfTypeIsNotByteArray() {
        HeadContext headContext = new HeadContext(outboundConsumer, config, pipeline, scheduler, () -> identity, validator);
        CompressedPublicKey recipient = mock(CompressedPublicKey.class);
        Object msg = mock(Object.class);
        CompletableFuture<Void> future = mock(CompletableFuture.class);

        when(future.isDone()).thenReturn(false);

        headContext.write(ctx, recipient, msg, future);

        verifyNoInteractions(outboundConsumer);
        verify(future).completeExceptionally(isA(IllegalArgumentException.class));
    }

    @Test
    void shouldNotWriteToConsumerWhenFutureIsDone() {
        HeadContext headContext = new HeadContext(outboundConsumer, config, pipeline, scheduler, () -> identity, validator);
        CompressedPublicKey recipient = mock(CompressedPublicKey.class);
        ApplicationMessage msg = mock(ApplicationMessage.class);
        CompletableFuture<Void> future = mock(CompletableFuture.class);

        when(future.isDone()).thenReturn(true);

        headContext.write(ctx, recipient, msg, future);

        verifyNoInteractions(outboundConsumer);
        verify(future, never()).complete(null);
    }

    @Test
    void shouldCompleteFutureExceptionallyIfExceptionOccursOnWrite() throws Exception {
        HeadContext headContext = new HeadContext(outboundConsumer, config, pipeline, scheduler, () -> identity, validator);
        CompressedPublicKey sender = mock(CompressedPublicKey.class);
        CompressedPublicKey recipient = mock(CompressedPublicKey.class);
        when(identity.getPublicKey()).thenReturn(sender);
        ObjectHolder msg = ObjectHolder.of(byte[].class, new byte[]{});
        CompletableFuture<Void> future = mock(CompletableFuture.class);

        doThrow(DrasylException.class).when(outboundConsumer).accept(any());
        when(future.isDone()).thenReturn(false);

        headContext.write(ctx, recipient, msg, future);

        verify(outboundConsumer).accept(eq(new ApplicationMessage(sender, recipient, msg.getObject(), msg.getClazz())));
        verify(future, never()).complete(null);
        verify(future).completeExceptionally(isA(Exception.class));
    }
}