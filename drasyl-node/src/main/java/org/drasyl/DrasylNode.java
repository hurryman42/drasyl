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
package org.drasyl;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.ChannelPromise;
import io.netty.channel.group.ChannelGroup;
import org.drasyl.annotation.Beta;
import org.drasyl.annotation.NonNull;
import org.drasyl.annotation.Nullable;
import org.drasyl.channel.DrasylChannel;
import org.drasyl.channel.DrasylNodeChannelInitializer;
import org.drasyl.channel.DrasylNodeServerChannelInitializer;
import org.drasyl.channel.DrasylServerChannel;
import org.drasyl.event.Event;
import org.drasyl.event.MessageEvent;
import org.drasyl.handler.serialization.MessageSerializer;
import org.drasyl.identity.DrasylAddress;
import org.drasyl.identity.Identity;
import org.drasyl.identity.IdentityManager;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.util.FutureUtil;
import org.drasyl.util.Version;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import static java.util.Objects.requireNonNull;
import static java.util.concurrent.CompletableFuture.completedFuture;
import static java.util.concurrent.CompletableFuture.failedFuture;
import static org.drasyl.Null.NULL;
import static org.drasyl.util.PlatformDependent.unsafeStaticFieldOffsetSupported;

/**
 * Represents a node in the drasyl Overlay Network. Applications that want to run on drasyl must
 * implement this class.
 * <p>
 * Example usage:
 * <pre><code>
 * DrasylNode node = new DrasylNode() {
 *   &#64;Override
 *   public void onEvent(Event event) {
 *     // handle incoming events (messages) here
 *     System.out.println("Event received: " + event);
 *   }
 * };
 * node.start();
 *
 * // wait till NodeOnlineEvent has been received
 *
 * // send message to another node
 * node.send("0229041b273dd5ee1c2bef2d77ae17dbd00d2f0a2e939e22d42ef1c4bf05147ea9", "Hello World");
 *
 * // shutdown node
 * node.shutdown();
 * </code></pre>
 */
@SuppressWarnings({ "java:S107", "java:S118" })
@Beta
public abstract class DrasylNode {
    private static final Logger LOG = LoggerFactory.getLogger(DrasylNode.class);
    private static String version;
    protected final Identity identity;
    protected final ServerBootstrap bootstrap;
    private ChannelFuture channelFuture;
    public ChannelGroup channels; // FIXME: make non-public!

    static {
        // https://github.com/netty/netty/issues/7817
        System.setProperty("io.netty.tryReflectionSetAccessible", "true");

        if (unsafeStaticFieldOffsetSupported()) {
            // dirty fix from Stack Overflow: https://stackoverflow.com/questions/46454995/how-to-hide-warning-illegal-reflective-access-in-java-9-without-jvm-argument/53517025#53517025
            try {
                final Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
                final Field field = unsafeClass.getDeclaredField("theUnsafe");
                field.setAccessible(true); // NOSONAR
                final Object unsafe = field.get(null);

                final Method putObjectVolatile = unsafeClass.getDeclaredMethod("putObjectVolatile", Object.class, long.class, Object.class);
                final Method staticFieldOffset = unsafeClass.getDeclaredMethod("staticFieldOffset", Field.class);

                final Class<?> loggerClass = Class.forName("jdk.internal.module.IllegalAccessLogger");
                final Field loggerField = loggerClass.getDeclaredField("logger");
                final Long offset = (Long) staticFieldOffset.invoke(unsafe, loggerField);
                putObjectVolatile.invoke(unsafe, loggerClass, offset, null);
            }
            catch (final Exception e) { // NOSONAR
                LOG.debug(e);
            }
        }
    }

    @SuppressWarnings("java:S2384")
    protected DrasylNode(final Identity identity,
                         final ServerBootstrap bootstrap,
                         final ChannelFuture channelFuture,
                         final ChannelGroup channels) {
        this.identity = requireNonNull(identity);
        this.bootstrap = requireNonNull(bootstrap);
        this.channelFuture = channelFuture;
        this.channels = channels;
    }

    /**
     * Creates a new drasyl Node with the given <code>config</code>. The node is only being created,
     * it neither connects to the Overlay * Network, nor can send or receive messages. To do this
     * you have to call {@link #start()}.
     * <p>
     * Note: This is a blocking method, because when a node is started for the first time, its
     * identity must be created. This can take up to a minute because of the proof of work.
     *
     * @param config custom configuration used for this node
     * @throws NullPointerException if {@code config} is {@code null}
     * @throws DrasylException      if identity could not be loaded or created
     */
    @SuppressWarnings({ "java:S2095" })
    protected DrasylNode(final DrasylConfig config) throws DrasylException {
        try {
            final IdentityManager identityManager = new IdentityManager(config);
            identityManager.loadOrCreateIdentity();
            identity = identityManager.getIdentity();
        }
        catch (final IOException e) {
            throw new DrasylException("Couldn't load or create identity", e);
        }

        bootstrap = new ServerBootstrap()
                .group(DrasylNodeSharedEventLoopGroupHolder.getParentGroup(), DrasylNodeSharedEventLoopGroupHolder.getChildGroup())
                .localAddress(identity)
                .channel(DrasylServerChannel.class)
                .handler(new DrasylNodeServerChannelInitializer(config, identity, this))
                .childHandler(new DrasylNodeChannelInitializer(config, this));

        LOG.debug("drasyl node with config `{}` and identity `{}` created", config, identity);
    }

    /**
     * Creates a new drasyl Node. The node is only being created, it neither connects to the Overlay
     * Network, nor can send or receive messages. To do this you have to call {@link #start()}.
     * <p>
     * Note: This is a blocking method, because when a node is started for the first time, its
     * identity must be created. This can take up to a minute because of the proof of work.
     *
     * @throws DrasylException       if identity could not be loaded or created
     * @throws DrasylConfigException if config is invalid
     */
    protected DrasylNode() throws DrasylException {
        this(DrasylConfig.of());
    }

    /**
     * Returns the version of the node. If the version could not be read, {@code null} is returned.
     *
     * @return the version of the node. If the version could not be read, {@code null} is returned
     * @deprecated Use {@code Version.identify().get("drasyl-core").version()} instead.
     */
    @Deprecated(since = "0.6.0", forRemoval = true)
    @SuppressWarnings("java:S2444")
    @Nullable
    public static String getVersion() {
        if (version == null) {
            version = Version.identify().get("drasyl-core").version();
        }

        return version;
    }

    /**
     * Sends <code>event</code> to the application and tells it information about the local node,
     * other peers, connections or incoming messages.
     *
     * @param event the event
     */
    public abstract void onEvent(@NonNull Event event);

    /**
     * Sends the content of {@code payload} to the identity {@code recipient}. Returns a failed
     * future with a {@link IllegalStateException} if the message could not be sent to the recipient
     * or a super peer. Important: Just because the future did not fail does not automatically mean
     * that the message could be delivered. Delivery confirmations must be implemented by the
     * application.
     *
     * <p>
     * <b>Note</b>: It is possible that the passed object cannot be serialized. In this case it is
     * not sent and the future is fulfilled with an exception. Serializable objects can be added on
     * start via the {@link DrasylConfig}.
     * </p>
     *
     * @param recipient the recipient of a message as compressed public key
     * @param payload   the payload of a message
     * @return a completion stage if the message was successfully processed, otherwise an
     * exceptionally completion stage
     * @see MessageSerializer
     * @since 0.1.3
     */
    @NonNull
    public CompletionStage<Void> send(@NonNull final String recipient,
                                      @Nullable final Object payload) {
        try {
            return send(IdentityPublicKey.of(recipient), payload);
        }
        catch (final IllegalArgumentException e) {
            return failedFuture(new DrasylException("Recipient does not conform to a valid public key.", e));
        }
    }

    /**
     * Sends the content of {@code payload} to the identity {@code recipient}. Returns a failed
     * future with a {@link IllegalStateException} if the message could not be sent to the recipient
     * or a super peer. Important: Just because the future did not fail does not automatically mean
     * that the message could be delivered. Delivery confirmations must be implemented by the
     * application.
     *
     * <p>
     * <b>Note</b>: It is possible that the passed object cannot be serialized. In this case it is
     * not sent and the future is fulfilled with an exception. Serializable objects can be added on
     * start via the {@link DrasylConfig}.
     * </p>
     *
     * @param recipient the recipient of a message
     * @param payload   the payload of a message
     * @return a completion stage if the message was successfully processed, otherwise an
     * exceptionally completion stage
     * @see MessageSerializer
     * @since 0.1.3
     */
    @SuppressWarnings("ReplaceNullCheck")
    @NonNull
    public CompletionStage<Void> send(@NonNull final DrasylAddress recipient,
                                      @Nullable final Object payload) {
        if (channelFuture != null && channelFuture.channel().isOpen()) {
            final CompletableFuture<Void> future = new CompletableFuture<>();
            if (identity.getAddress().equals(recipient)) {
                LOG.trace("Outbound message `{}` is addressed to us. Convert to inbound message.", () -> payload);
                channelFuture.channel().eventLoop().execute(() -> {
                    final MessageEvent event = MessageEvent.of(identity.getIdentityPublicKey(), payload);
                    onEvent(event);
                    future.complete(null);
                });
            }
            else {
                resolve(recipient).thenAccept(c -> {
                    final Object p;
                    if (payload == null) {
                        p = NULL;
                    }
                    else {
                        p = payload;
                    }

                    final ChannelPromise promise = c.newPromise();
                    c.writeAndFlush(p, promise);

                    FutureUtil.synchronizeFutures(promise, future);
                });
            }

            return future;
        }
        else {
            return failedFuture(new Exception("You have to call DrasylNode#start() first!"));
        }
    }

    /**
     * Creates a future containing a {@link Channel} for communication with {@code address}.
     * <p>
     * Note: be aware that the returned channel can be closed on inactivity according to {@link
     * DrasylConfig#getChannelInactivityTimeout()}. A closed channel can no longer be used. However,
     * a new channel can be created via this method.
     *
     * @param address peer address used for {@link Channel} creation
     * @return future containing {@link Channel} for {@code address} on completion
     */
    @NonNull
    public CompletionStage<Channel> resolve(@NonNull final DrasylAddress address) {
        if (channelFuture != null && channelFuture.channel().isOpen()) {
            final CompletableFuture<Channel> future = new CompletableFuture<>();
            // synchronize resolve by placing it in the ServerChannels's EventLoop
            channelFuture.channel().eventLoop().execute(() -> {
                // look for existing channel
                for (final Channel channel : channels) {
                    if (address.equals(channel.remoteAddress())) {
                        future.complete(channel);
                        return;
                    }
                }

                // no channel present, create new one
                final DrasylChannel channel = new DrasylChannel(channelFuture.channel(), (IdentityPublicKey) address);
                channels.add(channel);
                channelFuture.channel().pipeline().fireChannelRead(channel);

                // delay future completion to make sure Channel's childHandler is done
                channel.eventLoop().execute(() -> future.complete(channel));
            });

            return future;
        }
        else {
            return failedFuture(new Exception("You have to call DrasylNode#start() first!"));
        }
    }

    /**
     * Creates a future containing a {@link Channel} for communication with {@code address}.
     * <p>
     * Note: be aware that the returned channel can be closed on inactivity according to {@link
     * DrasylConfig#getChannelInactivityTimeout()}. A closed channel can no longer be used. However,
     * a new channel can be created via this method.
     *
     * @param address peer address used for {@link Channel} creation
     * @return future containing {@link Channel} for {@code address} on completion
     */
    @NonNull
    public CompletionStage<Channel> resolve(@NonNull final String address) {
        try {
            return resolve(IdentityPublicKey.of(address));
        }
        catch (final IllegalArgumentException e) {
            return failedFuture(new DrasylException("address does not conform to a valid public key.", e));
        }
    }

    /**
     * Shut the drasyl node down.
     * <p>
     * If there is a connection to a Super Peer, our node will deregister from that Super Peer.
     * <p>
     * If the local server has been started, it will now be stopped.
     * <p>
     * This method does not stop the shared threads. To kill the shared threads, you have to call
     * the {@link DrasylNodeSharedEventLoopGroupHolder#shutdown()} method.
     * <p>
     *
     * @return this method returns a future, which complements if all shutdown steps have been
     * completed.
     */
    @NonNull
    @SuppressWarnings("java:S1905")
    public synchronized CompletableFuture<Void> shutdown() {
        if (channelFuture != null) {
            try {
                return FutureUtil.toFuture(channelFuture.channel().close());
            }
            finally {
                channelFuture = null;
            }
        }
        else {
            return completedFuture(null);
        }
    }

    /**
     * Start the drasyl node.
     * <p>
     * First, the identity of the node is loaded. If none exists, a new one is generated.
     * <p>
     * If activated, a local server is started. This allows other nodes to discover our node.
     * <p>
     * If a super peer has been configured, a client is started which connects to this super peer.
     * Our node uses the Super Peer to discover and communicate with other nodes.
     * <p>
     *
     * @return this method returns a future, which complements if all components necessary for the
     * operation have been started.
     */
    @NonNull
    @SuppressWarnings("java:S1905")
    public synchronized CompletableFuture<Void> start() {
        if (channelFuture == null) {
            channelFuture = bootstrap.bind();
            return FutureUtil.toFuture(channelFuture);
        }
        else {
            return completedFuture(null);
        }
    }

    /**
     * Returns the {@link ChannelPipeline} to allow users to add own handlers.
     *
     * @return the pipeline
     */
    @Nullable
    public ChannelPipeline pipeline() {
        if (channelFuture != null) {
            return channelFuture.channel().pipeline();
        }
        else {
            return null;
        }
    }

    /**
     * Returns the {@link Identity} of this node.
     *
     * @return the {@link Identity} of this node
     */
    @NonNull
    public Identity identity() {
        return identity;
    }
}