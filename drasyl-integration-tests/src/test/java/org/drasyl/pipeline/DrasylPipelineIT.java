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

import io.reactivex.rxjava3.exceptions.UndeliverableException;
import io.reactivex.rxjava3.observers.TestObserver;
import io.reactivex.rxjava3.plugins.RxJavaPlugins;
import io.reactivex.rxjava3.subjects.PublishSubject;
import org.drasyl.crypto.CryptoException;
import org.drasyl.event.Event;
import org.drasyl.event.MessageEvent;
import org.drasyl.identity.Identity;
import org.drasyl.peer.connection.message.ApplicationMessage;
import org.drasyl.util.Pair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;

class DrasylPipelineIT {
    private PublishSubject<Event> receivedEvents;
    private PublishSubject<ApplicationMessage> outboundMessages;
    private DrasylPipeline pipeline;
    private Identity identity1;
    private Identity identity2;
    private byte[] payload;

    @BeforeEach
    void setup() throws CryptoException {
        receivedEvents = PublishSubject.create();
        outboundMessages = PublishSubject.create();

        identity1 = Identity.of(169092, "030a59784f88c74dcd64258387f9126739c3aeb7965f36bb501ff01f5036b3d72b", "0f1e188d5e3b98daf2266d7916d2e1179ae6209faa7477a2a66d4bb61dab4399");
        identity2 = Identity.of(26778671, "0236fde6a49564a0eaa2a7d6c8f73b97062d5feb36160398c08a5b73f646aa5fe5", "093d1ee70518508cac18eaf90d312f768c14d43de9bfd2618a2794d8df392da0");

        payload = new byte[]{
                0x01,
                0x02,
                0x03
        };

        pipeline = new DrasylPipeline(receivedEvents::onNext, outboundMessages::onNext);
    }

    @Test
    void passMessageThroughThePipeline() {
        TestObserver<Event> events = receivedEvents.test();

        byte[] newPayload = new byte[]{
                0x05
        };

        pipeline.addLast("msgChanger", new InboundHandlerAdapter() {
            @Override
            public void read(HandlerContext ctx, ApplicationMessage msg) {
                ApplicationMessage newMsg = new ApplicationMessage(identity2.getPublicKey(), msg.getRecipient(), newPayload);
                super.read(ctx, newMsg);
            }
        });

        ApplicationMessage msg = new ApplicationMessage(identity1.getPublicKey(), identity2.getPublicKey(), payload);

        pipeline.executeInbound(msg);

        events.awaitCount(1);
        events.assertValue(new MessageEvent(Pair.of(identity2.getPublicKey(), newPayload)));
    }

    @Test
    void passEventThroughThePipeline() {
        TestObserver<Event> events = receivedEvents.test();

        Event testEvent = new Event() {
        };

        pipeline.addLast("eventProducer", new InboundHandlerAdapter() {
            @Override
            public void read(HandlerContext ctx, ApplicationMessage msg) {
                super.read(ctx, msg);
                ctx.fireEventTriggered(testEvent);
            }
        });

        ApplicationMessage msg = new ApplicationMessage(identity1.getPublicKey(), identity2.getPublicKey(), payload);

        pipeline.executeInbound(msg);

        events.awaitCount(2);
        events.assertValueAt(0, new MessageEvent(Pair.of(msg.getSender(), msg.getPayload())));
        events.assertValueAt(1, testEvent);
    }

    @Test
    void exceptionShouldPassThroughThePipeline() {
        PublishSubject<Throwable> receivedExceptions = PublishSubject.create();
        TestObserver<Throwable> exceptions = receivedExceptions.test();

        RuntimeException exception = new RuntimeException("Error!");
        RxJavaPlugins.setErrorHandler(e -> {
            assertThat(e, instanceOf(UndeliverableException.class));
            assertThat(e.getCause(), instanceOf(PipelineException.class));
            assertThat(e.getCause().getCause(), instanceOf(RuntimeException.class));
            assertEquals(exception.getMessage(), e.getCause().getCause().getMessage());
        });

        pipeline.addLast("exceptionProducer", new InboundHandlerAdapter() {
            @Override
            public void read(HandlerContext ctx, ApplicationMessage msg) {
                super.read(ctx, msg);
                throw exception;
            }
        });

        pipeline.addLast("exceptionCatcher", new InboundHandlerAdapter() {
            @Override
            public void exceptionCaught(HandlerContext ctx, Exception cause) {
                exceptions.onNext(cause);
                super.exceptionCaught(ctx, cause);
            }
        });

        ApplicationMessage msg = new ApplicationMessage(identity1.getPublicKey(), identity2.getPublicKey(), payload);

        pipeline.executeInbound(msg);

        exceptions.awaitCount(1);
        exceptions.assertValue(exception);
    }

    @Test
    void passOutboundThroughThePipeline() {
        TestObserver<ApplicationMessage> outbounds = outboundMessages.test();

        byte[] newPayload = new byte[]{
                0x05
        };

        ApplicationMessage msg = new ApplicationMessage(identity1.getPublicKey(), identity2.getPublicKey(), payload);
        ApplicationMessage newMsg = new ApplicationMessage(identity2.getPublicKey(), msg.getRecipient(), newPayload);

        pipeline.addLast("outboundChanger", new OutboundHandlerAdapter() {
            @Override
            public void write(HandlerContext ctx,
                              ApplicationMessage msg,
                              CompletableFuture<Void> future) {
                super.write(ctx, newMsg, future);
            }
        });

        pipeline.executeOutbound(msg);

        outbounds.awaitCount(1);
        outbounds.assertValue(newMsg);
    }

    @Test
    void shouldNotPassthroughsMessagesWithDoneFuture() {
        TestObserver<ApplicationMessage> outbounds = outboundMessages.test();
        ApplicationMessage msg = new ApplicationMessage(identity1.getPublicKey(), identity2.getPublicKey(), payload);

        pipeline.addLast("outbound", new OutboundHandlerAdapter() {
            @Override
            public void write(HandlerContext ctx,
                              ApplicationMessage msg,
                              CompletableFuture<Void> future) {
                super.write(ctx, msg, CompletableFuture.completedFuture(null));
            }
        });

        pipeline.executeOutbound(msg);

        outbounds.awaitCount(1);
        outbounds.assertNoValues();
    }

    @Test
    void shouldNotPassthroughsMessagesWithExceptionallyFuture() {
        TestObserver<ApplicationMessage> outbounds = outboundMessages.test();
        ApplicationMessage msg = new ApplicationMessage(identity1.getPublicKey(), identity2.getPublicKey(), payload);

        pipeline.addLast("outbound", new OutboundHandlerAdapter() {
            @Override
            public void write(HandlerContext ctx,
                              ApplicationMessage msg,
                              CompletableFuture<Void> future) {
                super.write(ctx, msg, CompletableFuture.failedFuture(new Exception("Error!")));
            }
        });

        pipeline.executeOutbound(msg);

        outbounds.awaitCount(1);
        outbounds.assertNoValues();
    }
}
