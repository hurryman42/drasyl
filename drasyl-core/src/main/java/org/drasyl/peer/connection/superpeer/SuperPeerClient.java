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
package org.drasyl.peer.connection.superpeer;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.reactivex.rxjava3.core.Observable;
import io.reactivex.rxjava3.subjects.BehaviorSubject;
import io.reactivex.rxjava3.subjects.Subject;
import org.drasyl.DrasylNodeConfig;
import org.drasyl.crypto.Crypto;
import org.drasyl.event.Event;
import org.drasyl.identity.Identity;
import org.drasyl.messenger.Messenger;
import org.drasyl.peer.PeersManager;
import org.drasyl.peer.connection.message.QuitMessage;
import org.drasyl.util.DrasylScheduler;
import org.drasyl.util.WebSocketUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import static java.lang.Thread.sleep;
import static org.drasyl.peer.connection.message.QuitMessage.CloseReason.REASON_SHUTTING_DOWN;

/**
 * This class represents the link between <code>DrasylNode</code> and the super peer. It is
 * responsible for maintaining the connection to the super peer and updates the data of the super
 * peer in {@link PeersManager}.
 */
@SuppressWarnings({ "java:S107", "java:S4818" })
public class SuperPeerClient implements AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(SuperPeerClient.class);
    private final DrasylNodeConfig config;
    private final EventLoopGroup workerGroup;
    private final Supplier<Identity> identitySupplier;
    private final Messenger messenger;
    private final PeersManager peersManager;
    private final Set<URI> endpoints;
    private final AtomicBoolean opened;
    private final AtomicInteger nextEndpointPointer;
    private final AtomicInteger nextRetryDelayPointer;
    private final Consumer<Event> eventConsumer;
    private final Function<Supplier<Set<URI>>, Thread> threadSupplier;
    private final Subject<Boolean> connected;
    private Channel clientChannel;

    SuperPeerClient(DrasylNodeConfig config,
                    Supplier<Identity> identitySupplier,
                    PeersManager peersManager,
                    Messenger messenger,
                    EventLoopGroup workerGroup,
                    Set<URI> endpoints,
                    AtomicBoolean opened,
                    AtomicInteger nextEndpointPointer,
                    AtomicInteger nextRetryDelayPointer,
                    Consumer<Event> eventConsumer,
                    Channel clientChannel,
                    Function<Supplier<Set<URI>>, Thread> threadSupplier,
                    Subject<Boolean> connected) {
        this.identitySupplier = identitySupplier;
        this.messenger = messenger;
        this.peersManager = peersManager;
        this.config = config;
        this.workerGroup = workerGroup;
        this.endpoints = endpoints;
        this.opened = opened;
        this.nextEndpointPointer = nextEndpointPointer;
        this.nextRetryDelayPointer = nextRetryDelayPointer;
        this.eventConsumer = eventConsumer;
        this.clientChannel = clientChannel;
        this.threadSupplier = threadSupplier;
        this.connected = connected;
    }

    public SuperPeerClient(DrasylNodeConfig config,
                           Supplier<Identity> identitySupplier,
                           PeersManager peersManager,
                           Messenger messenger,
                           EventLoopGroup workerGroup,
                           Consumer<Event> eventConsumer) throws SuperPeerClientException {
        endpoints = config.getSuperPeerEndpoints();

        if (endpoints.isEmpty()) {
            throw new SuperPeerClientException("At least one Super Peer Endpoint must be specified.");
        }

        this.identitySupplier = identitySupplier;
        this.messenger = messenger;
        this.peersManager = peersManager;
        this.config = config;
        this.workerGroup = workerGroup;
        this.opened = new AtomicBoolean(false);
        // The pointer should point to a random endpoint. This creates a distribution on different super peer's endpoints
        this.nextEndpointPointer = new AtomicInteger(endpoints.isEmpty() ? 0 : Crypto.randomNumber(endpoints.size()));
        this.nextRetryDelayPointer = new AtomicInteger(0);
        this.eventConsumer = eventConsumer;
        this.threadSupplier = myEndpoints -> new Thread(this::keepConnectionAlive);
        this.connected = BehaviorSubject.createDefault(false);
    }

    void keepConnectionAlive() {
        do {
            URI endpoint = getEndpoint();
            LOG.debug("Connect to Super Peer Endpoint '{}'", endpoint);
            try {
                ChannelInitializer<SocketChannel> channelInitializer = new SuperPeerClientChannelBootstrap(config, this, endpoint).getChannelInitializer();

                ChannelFuture channelFuture = new Bootstrap()
                        .group(workerGroup)
                        .channel(NioSocketChannel.class)
                        .handler(channelInitializer)
                        .connect(endpoint.getHost(), WebSocketUtil.webSocketPort(endpoint));
                channelFuture.awaitUninterruptibly();

                if (channelFuture.isSuccess()) {
                    clientChannel = channelFuture.channel();
                    clientChannel.closeFuture().syncUninterruptibly();
                }
                else {
                    throw new SuperPeerClientException(channelFuture.cause());
                }
            }
            catch (SuperPeerClientException e) {
                LOG.warn("Error while trying to connect to Super Peer:", e);
            }
            catch (IllegalStateException e) {
                LOG.debug("Working Group has rejected the new bootstrap. Maybe the node is shutting down.");
                Thread.currentThread().interrupt();
                break;
            }
        } while (retryConnection() && doRetryCycle()); //NOSONAR
    }

    /**
     * Returns the next Super Peer's endpoint. Iterates over list of all endpoints specified in
     * configuration. Jumps back to start when end of list is reached.
     *
     * @return
     */
    private URI getEndpoint() {
        URI[] myEndpoints = endpoints.toArray(new URI[0]);
        return myEndpoints[nextEndpointPointer.get()];
    }

    /**
     * This message blocks until the client should make another connect attempt and then returns
     * <code>true</code. Otherwise <code>false</code> is returned.
     *
     * @return
     */
    boolean retryConnection() {
        if (opened.get() && !config.getSuperPeerRetryDelays().isEmpty()) {
            try {
                Duration duration = retryDelay();
                LOG.debug("Wait {}ms before retry connect to Super Peer", duration.toMillis());
                sleep(duration.toMillis());
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            return true;
        }
        else {
            return false;
        }
    }

    /**
     * Increases the internal counters for retries. Ensures that the client iterates over the
     * available Super Peer endpoints and throttles the speed of attempts to reconnect. Always
     * returns <code>true</code>.
     *
     * @return
     */
    boolean doRetryCycle() {
        nextEndpointPointer.updateAndGet(p -> (p + 1) % endpoints.size());
        List<Duration> delays = config.getSuperPeerRetryDelays();
        nextRetryDelayPointer.updateAndGet(p -> Math.min(p + 1, delays.size() - 1));
        return true;
    }

    /**
     * Returns the duration of delay before the client should make a new attempt to reconnect to
     * Super Peer. Iterates over list of all delays specified in configuration. Uses last element
     * permanently when end of list is reached. If list is empty, a {@link IllegalArgumentException}
     * is thrown.
     *
     * @return
     */
    Duration retryDelay() {
        return config.getSuperPeerRetryDelays().get(nextRetryDelayPointer.get());
    }

    /**
     * Returns an observable which emits the value <code>true</code> if a connection with the super
     * peer including handshake could be established. Otherwise <code>false</code> is returned.
     * <p>
     * The Observable immediately returns an item with the current state of the connection on a new
     * subscription.
     *
     * @return
     */
    public Observable<Boolean> connectionEstablished() {
        return connected.subscribeOn(DrasylScheduler.getInstance());
    }

    public void open(Supplier<Set<URI>> ownEndpointsSupplier) {
        if (opened.compareAndSet(false, true)) {
            threadSupplier.apply(ownEndpointsSupplier).start();
        }
    }

    Identity getIdentity() {
        return identitySupplier.get();
    }

    Messenger getMessenger() {
        return messenger;
    }

    PeersManager getPeersManager() {
        return peersManager;
    }

    Consumer<Event> getEventConsumer() {
        return eventConsumer;
    }

    Subject<Boolean> getConnected() {
        return connected;
    }

    @Override
    public void close() {
        if (opened.compareAndSet(true, false) && clientChannel != null && clientChannel.isOpen()) {
            // send quit message and close connections
            clientChannel.writeAndFlush(new QuitMessage(REASON_SHUTTING_DOWN)).addListener(ChannelFutureListener.CLOSE);

            clientChannel.closeFuture().syncUninterruptibly();
            clientChannel = null;
        }
    }
}
