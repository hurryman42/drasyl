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
package org.drasyl.peer.connection.client;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.reactivex.rxjava3.subjects.Subject;
import org.drasyl.DrasylConfig;
import org.drasyl.DrasylException;
import org.drasyl.event.Event;
import org.drasyl.peer.connection.message.QuitMessage;
import org.drasyl.util.DrasylFunction;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static java.time.Duration.ofSeconds;
import static org.drasyl.peer.connection.message.QuitMessage.CloseReason.REASON_SHUTTING_DOWN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SuperPeerClientTest {
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private DrasylConfig config;
    @Mock
    private EventLoopGroup workerGroup;
    @Mock
    private Set<URI> endpoints;
    @Mock
    private AtomicBoolean opened;
    @Mock
    private AtomicInteger nextEndpointPointer;
    @Mock
    private AtomicInteger nextRetryDelayPointer;
    @Mock
    private Consumer<Event> onEvent;
    @Mock
    private Supplier<Bootstrap> bootstrapSupplier;
    @Mock
    private List<Duration> superPeerRetryDelays;
    @Mock
    private Channel channel;
    @Mock
    private ChannelFuture channelFuture;
    @Mock
    private Subject<Boolean> connected;
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private Bootstrap bootstrap;
    @Mock
    private ChannelInitializer<SocketChannel> channelInitializer;
    @Mock
    private DrasylFunction<URI, ChannelInitializer<SocketChannel>, DrasylException> channelInitializerSupplier;

    @Nested
    class Open {
        @Test
        void shouldConnectIfClientIsNotAlreadyOpen() {
            when(bootstrapSupplier.get()).thenReturn(bootstrap);
            endpoints = Set.of(URI.create("ws://localhost"));

            SuperPeerClient client = new SuperPeerClient(config, workerGroup, endpoints, new AtomicBoolean(false), nextEndpointPointer, nextRetryDelayPointer, bootstrapSupplier, connected, channelInitializerSupplier, channelInitializer, channel);
            client.open();

            verify(bootstrapSupplier).get();
        }

        @Test
        void shouldNotConnectIfClientIsAlreadyOpen() {
            SuperPeerClient client = new SuperPeerClient(config, workerGroup, endpoints, new AtomicBoolean(true), nextEndpointPointer, nextRetryDelayPointer, bootstrapSupplier, connected, channelInitializerSupplier, channelInitializer, channel);
            client.open();

            verify(bootstrapSupplier, never()).get();
        }
    }

    @Nested
    class ConditionalScheduledReconnect {
        @Test
        void shouldScheduleReconnectIfClientIsOpenAndSuperPeerRetryDelaysIsNotEmpty() {
            when(config.getSuperPeerRetryDelays()).thenReturn(List.of(ofSeconds(1)));

            SuperPeerClient client = new SuperPeerClient(config, workerGroup, endpoints, new AtomicBoolean(true), nextEndpointPointer, new AtomicInteger(), bootstrapSupplier, connected, channelInitializerSupplier, channelInitializer, channel);
            client.conditionalScheduledReconnect();

            verify(workerGroup).schedule(any(Runnable.class), anyLong(), any(TimeUnit.class));
        }

        @Test
        void shouldNotScheduleReconnectIfClientIsNotOpen() {
            SuperPeerClient client = new SuperPeerClient(config, workerGroup, endpoints, new AtomicBoolean(false), nextEndpointPointer, nextRetryDelayPointer, bootstrapSupplier, connected, channelInitializerSupplier, channelInitializer, channel);
            client.conditionalScheduledReconnect();

            verify(workerGroup, never()).schedule(any(Runnable.class), anyLong(), any(TimeUnit.class));
        }
    }

    @Nested
    class NextEndpoint {
        @Test
        void shouldReturnCorrectEndpoint() {
            endpoints = new TreeSet();
            endpoints.add(URI.create("ws://node1.org"));
            endpoints.add(URI.create("ws://node2.org"));

            SuperPeerClient client = new SuperPeerClient(config, workerGroup, endpoints, opened, new AtomicInteger(0), nextRetryDelayPointer, bootstrapSupplier, connected, channelInitializerSupplier, channelInitializer, channel);

            assertEquals(URI.create("ws://node1.org"), client.nextEndpoint());
            assertEquals(URI.create("ws://node2.org"), client.nextEndpoint());
            assertEquals(URI.create("ws://node1.org"), client.nextEndpoint());
        }
    }

    @Nested
    class NextRetryDelay {
        @Test
        void shouldReturnCorrectDelay() {
            when(config.getSuperPeerRetryDelays()).thenReturn(superPeerRetryDelays);
            when(config.getSuperPeerRetryDelays()).thenReturn(List.of(ofSeconds(3), ofSeconds(6)));

            SuperPeerClient client = new SuperPeerClient(config, workerGroup, endpoints, opened, nextEndpointPointer, new AtomicInteger(0), bootstrapSupplier, connected, channelInitializerSupplier, channelInitializer, channel);

            assertEquals(ofSeconds(3), client.nextRetryDelay());
            assertEquals(ofSeconds(6), client.nextRetryDelay());
            assertEquals(ofSeconds(6), client.nextRetryDelay());
        }
    }

    @Nested
    class Close {
        @Test
        void shouldCloseConnectionIfClientIsOpen() {
            when(channel.isOpen()).thenReturn(true);
            when(channel.closeFuture()).thenReturn(channelFuture);
            when(channel.writeAndFlush(any())).thenReturn(channelFuture);

            SuperPeerClient client = new SuperPeerClient(config, workerGroup, endpoints, new AtomicBoolean(true), nextEndpointPointer, nextRetryDelayPointer, bootstrapSupplier, connected, channelInitializerSupplier, channelInitializer, channel);

            client.close();

            verify(channel).writeAndFlush(new QuitMessage(REASON_SHUTTING_DOWN));
            verify(channel).closeFuture();
        }

        @Test
        void shouldNotCloseConnectionIfClientIsNotOpen() {
            SuperPeerClient client = new SuperPeerClient(config, workerGroup, endpoints, new AtomicBoolean(false), nextEndpointPointer, nextRetryDelayPointer, bootstrapSupplier, connected, channelInitializerSupplier, channelInitializer, channel);

            client.close();

            verify(channel, never()).writeAndFlush(new QuitMessage(REASON_SHUTTING_DOWN));
            verify(channel, never()).close();
        }
    }
}
