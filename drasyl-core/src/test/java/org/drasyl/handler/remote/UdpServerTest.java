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
package org.drasyl.handler.remote;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.PendingWriteQueue;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.socket.DatagramPacket;
import org.drasyl.channel.AddressedMessage;
import org.drasyl.identity.Identity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.mockito.Answers.RETURNS_DEEP_STUBS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UdpServerTest {
    @Mock(answer = RETURNS_DEEP_STUBS)
    private Identity identity;
    @Mock(answer = RETURNS_DEEP_STUBS)
    private Bootstrap bootstrap;
    @Mock(answer = RETURNS_DEEP_STUBS)
    private Channel channel;
    private InetAddress bindHost;
    private final int bindPort = 22527;
    private PendingWriteQueue pendingWrites;

    @BeforeEach
    void setUp() throws UnknownHostException {
        bindHost = InetAddress.getLocalHost();
    }

    @Nested
    class StartServer {
        @Test
        void shouldStartServerOnChannelActive(@Mock(answer = RETURNS_DEEP_STUBS) final ChannelFuture channelFuture) {
            when(channelFuture.isSuccess()).thenReturn(true);
            when(channelFuture.channel().localAddress()).thenReturn(new InetSocketAddress(22527));
            when(bootstrap.group(any()).channel(any()).handler(any()).bind(any(InetAddress.class), anyInt()).addListener(any())).then(invocation -> {
                final ChannelFutureListener listener = invocation.getArgument(0, ChannelFutureListener.class);
                listener.operationComplete(channelFuture);
                return null;
            });

            final UdpServer handler = new UdpServer(bootstrap, bindHost, bindPort, pendingWrites, null);
            final EmbeddedChannel channel = new EmbeddedChannel(handler);
            try {
                verify(bootstrap.group(any()).channel(any()).handler(any())).bind(any(InetAddress.class), anyInt());
            }
            finally {
                channel.close();
            }
        }
    }

    @Nested
    class StopServer {
        @Test
        void shouldStopServerOnChannelInactive() {
            when(channel.localAddress()).thenReturn(new InetSocketAddress(22527));

            final UdpServer handler = new UdpServer(bootstrap, bindHost, bindPort, pendingWrites, channel);
            final EmbeddedChannel channel = new EmbeddedChannel(handler);
            try {
                channel.pipeline().fireChannelInactive();

                verify(UdpServerTest.this.channel).close();
            }
            finally {
                channel.close();
            }
        }
    }

    @Nested
    class MessagePassing {
        @Test
        void shouldPassOutgoingMessagesToUdp(@Mock(answer = RETURNS_DEEP_STUBS) final ByteBuf msg) {
            when(channel.isWritable()).thenReturn(true);

            final SocketAddress recipient = new InetSocketAddress(1234);

            final UdpServer handler = new UdpServer(bootstrap, bindHost, bindPort, pendingWrites, channel);
            final EmbeddedChannel channel = new EmbeddedChannel(handler);
            try {
                channel.writeAndFlush(new AddressedMessage<>(msg, recipient));

                verify(UdpServerTest.this.channel).writeAndFlush(any());
            }
            finally {
                channel.close();
            }
        }

        @Test
        @SuppressWarnings("unchecked")
        void shouldPassIngoingMessagesToPipeline(@Mock final ChannelHandlerContext channelCtx,
                                                 @Mock(answer = RETURNS_DEEP_STUBS) final ChannelFuture channelFuture,
                                                 @Mock final ByteBuf message) {
            when(bootstrap.group(any()).channel(any()).handler(any())).then((Answer<Bootstrap>) invocation -> {
                final SimpleChannelInboundHandler<DatagramPacket> handler = invocation.getArgument(0, SimpleChannelInboundHandler.class);
                handler.channelRead(channelCtx, new DatagramPacket(message, new InetSocketAddress(22527), new InetSocketAddress(25421)));
                return bootstrap;
            });
            when(bootstrap.group(any()).channel(any()).bind(any(InetAddress.class), anyInt())).thenReturn(channelFuture);
            when(channelFuture.channel().localAddress()).thenReturn(new InetSocketAddress(22527));

            final UdpServer handler = new UdpServer(bootstrap, bindHost, bindPort, pendingWrites, null);

            final EmbeddedChannel channel = new EmbeddedChannel(handler);
            try {
                channel.pipeline().fireChannelActive();

                final AddressedMessage<Object, SocketAddress> actual = channel.readInbound();
                assertThat(actual.message(), instanceOf(ByteBuf.class));

                actual.release();
            }
            finally {
                channel.close();
            }
        }
    }
}
