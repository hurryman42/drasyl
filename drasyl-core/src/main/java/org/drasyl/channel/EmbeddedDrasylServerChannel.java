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
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;
import io.reactivex.rxjava3.core.Observable;
import io.reactivex.rxjava3.subjects.ReplaySubject;
import io.reactivex.rxjava3.subjects.Subject;
import org.drasyl.DrasylAddress;
import org.drasyl.DrasylConfig;
import org.drasyl.event.Event;
import org.drasyl.event.MessageEvent;
import org.drasyl.identity.Identity;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.peer.PeersManager;
import org.drasyl.pipeline.address.Address;
import org.drasyl.pipeline.message.AddressedEnvelope;
import org.drasyl.pipeline.message.DefaultAddressedEnvelope;
import org.drasyl.pipeline.serialization.Serialization;
import org.drasyl.util.FutureUtil;
import org.drasyl.util.RandomUtil;
import org.drasyl.util.ReferenceCountUtil;
import org.drasyl.util.TypeReference;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.drasyl.channel.Null.NULL;

/**
 * A {@link EmbeddedChannel} based on a {@link EmbeddedDrasylServerChannel}.
 */
public class EmbeddedDrasylServerChannel extends EmbeddedChannel implements DrasylServerChannel {
    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    public static final
    Optional<Object> NULL_MESSAGE = Optional.empty();
    private final DrasylConfig config;
    private final Identity identity;
    private final PeersManager peersManager;
    protected final Serialization inboundSerialization;
    protected final Serialization outboundSerialization;
    private final Subject<AddressedEnvelope<Address, Object>> inboundMessages;
    private final Subject<Event> inboundEvents;
    private final Subject<AddressedEnvelope<Address, Object>> outboundMessages;

    public EmbeddedDrasylServerChannel(final DrasylConfig config,
                                       final Identity identity,
                                       final PeersManager peersManager,
                                       final Serialization inboundSerialization,
                                       final Serialization outboundSerialization,
                                       final Subject<AddressedEnvelope<Address, Object>> inboundMessages,
                                       final Subject<Event> inboundEvents,
                                       final Subject<AddressedEnvelope<Address, Object>> outboundMessages,
                                       final ChannelHandler... handlers) {
        this.config = config;
        this.identity = identity;
        this.peersManager = peersManager;
        this.inboundSerialization = inboundSerialization;
        this.outboundSerialization = outboundSerialization;
        this.inboundMessages = inboundMessages;
        this.inboundEvents = inboundEvents;
        this.outboundMessages = outboundMessages;

        // my tail
        pipeline().addLast("MY_TAIL", new ChannelInboundHandlerAdapter() {
            @Override
            public void channelRead(final ChannelHandlerContext ctx,
                                    final Object msg) throws Exception {
                if (msg instanceof MigrationInboundMessage) {
                    final MigrationInboundMessage<?, ?> m = (MigrationInboundMessage<?, ?>) msg;
                    Object message = m.message();
                    if (message == NULL) {
                        message = null;
                    }
                    if (m.address() instanceof IdentityPublicKey) {
                        final IdentityPublicKey senderAddress = (IdentityPublicKey) m.address();
                        inboundEvents.onNext(MessageEvent.of(senderAddress, message));
                    }
                    inboundMessages.onNext(new DefaultAddressedEnvelope<>(m.address(), null, message));

                    m.future().complete(null);
                }
                else {
                    super.channelRead(ctx, msg);
                }
            }

            @Override
            public void userEventTriggered(final ChannelHandlerContext ctx,
                                           final Object evt) throws Exception {
                if (evt instanceof MigrationEvent) {
                    final MigrationEvent e = (MigrationEvent) evt;
                    inboundEvents.onNext(e.event());
                    e.future().complete(null);
                }
                else {
                    super.userEventTriggered(ctx, evt);
                }
            }
        });

        // my head
        pipeline().addFirst("MY_HEAD", new ChannelOutboundHandlerAdapter() {
            @Override
            public void write(final ChannelHandlerContext ctx,
                              final Object msg,
                              final ChannelPromise promise) throws Exception {
                if (msg instanceof MigrationOutboundMessage) {
                    final MigrationOutboundMessage<?, ?> m = (MigrationOutboundMessage<?, ?>) msg;
                    Object message = m.message();
                    if (message == NULL) {
                        message = null;
                    }
                    outboundMessages.onNext(new DefaultAddressedEnvelope<>(null, m.address(), message));
                    promise.setSuccess();
                }
                else {
                    super.write(ctx, msg, promise);
                }
            }
        });

        pipeline().addLast(new ChannelInitializer<>() {
            @Override
            protected void initChannel(final Channel ch) {
                final ChannelPipeline pipeline = ch.pipeline();
                for (final ChannelHandler h : handlers) {
                    if (h == null) {
                        break;
                    }
                    pipeline.addBefore("MY_TAIL", RandomUtil.randomString(5), h);
                }
            }
        });
    }

    public EmbeddedDrasylServerChannel(final DrasylConfig config,
                                       final Identity identity,
                                       final PeersManager peersManager,
                                       final ChannelHandler... handlers) {
        this(
                config,
                identity,
                peersManager,
                new Serialization(config.getSerializationSerializers(), config.getSerializationsBindingsInbound()),
                new Serialization(config.getSerializationSerializers(), config.getSerializationsBindingsOutbound()),
                ReplaySubject.<AddressedEnvelope<Address, Object>>create().toSerialized(),
                ReplaySubject.<Event>create().toSerialized(),
                ReplaySubject.<AddressedEnvelope<Address, Object>>create().toSerialized(),
                handlers
        );
    }

    /**
     * @return all messages of type {@code T} that passes the pipeline until the end
     */
    @SuppressWarnings("unchecked")
    public <T> Observable<T> drasylInboundMessages(final Class<T> clazz) {
        return (Observable<T>) inboundMessages.map(m -> m.getContent() != null ? m.getContent() : NULL_MESSAGE).filter(clazz::isInstance);
    }

    /**
     * @return all messages of type {@code T} that passes the pipeline until the end
     */
    @SuppressWarnings("unchecked")
    public <T> Observable<T> drasylInboundMessages(final TypeReference<T> typeReference) {
        return (Observable<T>) inboundMessages.map(m -> m.getContent() != null ? m.getContent() : NULL_MESSAGE).filter(m -> isInstance(typeReference.getType(), m));
    }

    public Observable<Object> drasylInboundMessages() {
        return inboundMessages.map(m -> m.getContent() != null ? m.getContent() : NULL_MESSAGE);
    }

    /**
     * @return all messages that passes the pipeline until the end
     */
    public Observable<AddressedEnvelope<Address, Object>> inboundMessagesWithSender() {
        return inboundMessages;
    }

    /**
     * @return all events that passes the pipeline until the end
     */
    public Observable<Event> inboundEvents() {
        return inboundEvents;
    }

    @SuppressWarnings("unchecked")
    public <T> Observable<T> drasylOutboundMessages(final Class<T> clazz) {
        return (Observable<T>) outboundMessages.map(m -> m.getContent() != null ? m.getContent() : NULL_MESSAGE).filter(clazz::isInstance);
    }

    @SuppressWarnings("unchecked")
    public <T> Observable<T> drasylOutboundMessages(final TypeReference<T> typeReference) {
        return (Observable<T>) outboundMessages.map(m -> m.getContent() != null ? m.getContent() : NULL_MESSAGE).filter(m -> isInstance(typeReference.getType(), m));
    }

    public Observable<Object> drasylOutboundMessages() {
        return outboundMessages.map(m -> m.getContent() != null ? m.getContent() : NULL_MESSAGE);
    }

    /**
     * @return all messages that passes the pipeline until the end
     */
    public Observable<AddressedEnvelope<Address, Object>> outboundMessagesWithRecipient() {
        return outboundMessages;
    }

    public void drasylClose() {
        outboundMessages.onComplete();
        inboundMessages.onComplete();
        inboundEvents.onComplete();

        outboundMessages.toList().blockingGet().forEach(o -> ReferenceCountUtil.safeRelease(o.getContent()));
        inboundMessages.toList().blockingGet().forEach(o -> ReferenceCountUtil.safeRelease(o.getContent()));

        close();
    }

    public CompletableFuture<Void> processInbound(final Address sender, final Object msg) {
        final ChannelPromise promise = newPromise();
        final CompletableFuture<Void> future = FutureUtil.toFuture(promise);
        pipeline().fireChannelRead(new MigrationInboundMessage<>(msg, sender, future));
        return future;
    }

    public CompletableFuture<Void> processInbound(final Event event) {
        final CompletableFuture<Void> future = new CompletableFuture<>();
        pipeline().fireUserEventTriggered(new MigrationEvent(event, future));
        runPendingTasks();
        return future;
    }

    public CompletableFuture<Void> processOutbound(final Address recipient, Object msg) {
        final ChannelPromise promise = newPromise();
        if (msg == null) {
            msg = NULL;
        }
        pipeline().writeAndFlush(new MigrationOutboundMessage<>(msg, recipient), promise);
        writeAndFlush(msg);
        return FutureUtil.toFuture(promise);
    }

    @Override
    public DrasylConfig drasylConfig() {
        return config;
    }

    @Override
    public PeersManager peersManager() {
        return peersManager;
    }

    @Override
    public Serialization inboundSerialization() {
        return inboundSerialization;
    }

    @Override
    public Serialization outboundSerialization() {
        return outboundSerialization;
    }

    @Override
    public Identity identity() {
        return identity;
    }

    @Override
    public Map<DrasylAddress, Channel> channels() {
        throw new RuntimeException("not implemented yet");
    }

    @Override
    public Channel getOrCreateChildChannel(final ChannelHandlerContext ctx,
                                           final IdentityPublicKey peer) {
        throw new RuntimeException("not implemented yet");
    }

    private static boolean isInstance(final Type type, final Object obj) {
        if (type instanceof Class<?>) {
            return ((Class<?>) type).isInstance(obj);
        }
        else if (type instanceof ParameterizedType) {
            final Type rawType = ((ParameterizedType) type).getRawType();
            return isInstance(rawType, obj);
        }
        return false;
    }
}
