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
package org.drasyl.remote.handler;

import io.netty.util.concurrent.Future;
import org.drasyl.channel.MigrationHandlerContext;
import org.drasyl.event.Event;
import org.drasyl.event.NodeDownEvent;
import org.drasyl.event.NodeUnrecoverableErrorEvent;
import org.drasyl.event.NodeUpEvent;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.pipeline.address.Address;
import org.drasyl.pipeline.address.InetSocketAddressWrapper;
import org.drasyl.pipeline.skeleton.SimpleDuplexHandler;
import org.drasyl.remote.protocol.DiscoveryMessage;
import org.drasyl.remote.protocol.Protocol.Discovery;
import org.drasyl.remote.protocol.RemoteMessage;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.drasyl.remote.handler.UdpMulticastServer.MULTICAST_ADDRESS;
import static org.drasyl.remote.handler.UdpMulticastServer.MULTICAST_INTERFACE;
import static org.drasyl.util.RandomUtil.randomLong;

/**
 * This handler, along with the {@link UdpMulticastServer}, is used to discover other nodes on the
 * local network.
 * <p>
 * For this purpose, the {@link UdpMulticastServer} joins a multicast group and forwards received
 * {@link Discovery} messages to this handler, which thus becomes aware of other nodes in the local
 * network. In case no {@link Discovery} message has been received for a longer period of time, the
 * other node is considered stale.
 * <p>
 * In addition, this handler periodically sends a {@link Discovery} messages to a multicast group so
 * that other nodes become aware of this node.
 *
 * @see UdpMulticastServer
 */
@SuppressWarnings("java:S110")
public class LocalNetworkDiscovery extends SimpleDuplexHandler<DiscoveryMessage, RemoteMessage, Address> {
    private static final Logger LOG = LoggerFactory.getLogger(LocalNetworkDiscovery.class);
    private static final Object path = LocalNetworkDiscovery.class;
    private final Map<IdentityPublicKey, Peer> peers;
    private Future pingDisposable;

    public LocalNetworkDiscovery(final Map<IdentityPublicKey, Peer> peers,
                                 final Future pingDisposable) {
        this.peers = requireNonNull(peers);
        this.pingDisposable = pingDisposable;
    }

    public LocalNetworkDiscovery() {
        this(new ConcurrentHashMap<>(), null);
    }

    @Override
    public void onEvent(final MigrationHandlerContext ctx,
                        final Event event,
                        final CompletableFuture<Void> future) {
        if (MULTICAST_INTERFACE != null) {
            if (event instanceof NodeUpEvent) {
                startHeartbeat(ctx);
            }
            else if (event instanceof NodeUnrecoverableErrorEvent || event instanceof NodeDownEvent) {
                stopHeartbeat();
                clearRoutes(ctx);
            }
        }

        // passthrough event
        ctx.passEvent(event, future);
    }

    synchronized void startHeartbeat(final MigrationHandlerContext ctx) {
        if (pingDisposable == null) {
            LOG.debug("Start Network Network Discovery...");
            final long pingInterval = ctx.config().getRemotePingInterval().toMillis();
            pingDisposable = ctx.independentScheduler().schedulePeriodicallyDirect(() -> doHeartbeat(ctx), randomLong(pingInterval), pingInterval, MILLISECONDS);
            LOG.debug("Network Discovery started.");
        }
    }

    synchronized void stopHeartbeat() {
        if (pingDisposable != null) {
            LOG.debug("Stop Network Host Discovery...");
            pingDisposable.cancel(false);
            pingDisposable = null;
            LOG.debug("Network Discovery stopped.");
        }
    }

    synchronized void clearRoutes(final MigrationHandlerContext ctx) {
        new HashMap<>(peers).forEach(((publicKey, peer) -> {
            ctx.peersManager().removePath(ctx, publicKey, path);
            peers.remove(publicKey);
        }));
        peers.clear();
    }

    void doHeartbeat(final MigrationHandlerContext ctx) {
        removeStalePeers(ctx);
        pingLocalNetworkNodes(ctx);
    }

    private void removeStalePeers(final MigrationHandlerContext ctx) {
        new HashMap<>(peers).forEach(((publicKey, peer) -> {
            if (peer.isStale(ctx)) {
                LOG.debug("Last contact from {} is {}ms ago. Remove peer.", () -> publicKey, () -> System.currentTimeMillis() - peer.getLastInboundPingTime());
                ctx.peersManager().removePath(ctx, publicKey, path);
                peers.remove(publicKey);
            }
        }));
    }

    @Override
    protected void matchedInbound(final MigrationHandlerContext ctx,
                                  final Address sender,
                                  final DiscoveryMessage msg,
                                  final CompletableFuture<Void> future) {
        if (pingDisposable != null && sender instanceof InetSocketAddressWrapper && msg.getRecipient() == null) {
            handlePing(ctx, sender, msg, future);
        }
        else {
            ctx.passInbound(sender, msg, future);
        }
    }

    private void handlePing(final MigrationHandlerContext ctx,
                            final Address sender,
                            final RemoteMessage msg,
                            final CompletableFuture<Void> future) {
        final IdentityPublicKey msgSender = msg.getSender();
        if (!ctx.identity().getIdentityPublicKey().equals(msgSender)) {
            LOG.debug("Got multicast discovery message for `{}` from address `{}`", msgSender, sender);
            final Peer peer = peers.computeIfAbsent(msgSender, key -> new Peer((InetSocketAddressWrapper) sender));
            peer.inboundPingOccurred();
            ctx.peersManager().addPath(ctx, msgSender, path);
        }

        future.complete(null);
    }

    @SuppressWarnings("SuspiciousMethodCalls")
    @Override
    protected void matchedOutbound(final MigrationHandlerContext ctx,
                                   final Address recipient,
                                   final RemoteMessage msg,
                                   final CompletableFuture<Void> future) throws Exception {
        final Peer peer = peers.get(recipient);
        if (peer != null) {
            LOG.trace("Send message `{}` via local network route `{}`.", () -> msg, peer::getAddress);
            ctx.passOutbound(peer.getAddress(), msg, future);
        }
        else {
            ctx.passOutbound(recipient, msg, future);
        }
    }

    private static void pingLocalNetworkNodes(final MigrationHandlerContext ctx) {
        final DiscoveryMessage messageEnvelope = DiscoveryMessage.of(ctx.config().getNetworkId(), ctx.identity().getIdentityPublicKey(), ctx.identity().getProofOfWork());
        LOG.debug("Send {} to {}", messageEnvelope, MULTICAST_ADDRESS);
        ctx.passOutbound(MULTICAST_ADDRESS, messageEnvelope, new CompletableFuture<>()).exceptionally(e -> {
            LOG.warn("Unable to send discovery message to multicast group `{}`", () -> MULTICAST_ADDRESS, () -> e);
            return null;
        });
    }

    static class Peer {
        private final InetSocketAddressWrapper address;
        private long lastInboundPingTime;

        Peer(final InetSocketAddressWrapper address,
             final long lastInboundPingTime) {
            this.address = requireNonNull(address);
            this.lastInboundPingTime = lastInboundPingTime;
        }

        public Peer(final InetSocketAddressWrapper address) {
            this(address, 0L);
        }

        public InetSocketAddressWrapper getAddress() {
            return address;
        }

        public void inboundPingOccurred() {
            lastInboundPingTime = System.currentTimeMillis();
        }

        public boolean isStale(final MigrationHandlerContext ctx) {
            return lastInboundPingTime < System.currentTimeMillis() - ctx.config().getRemotePingTimeout().toMillis();
        }

        public long getLastInboundPingTime() {
            return lastInboundPingTime;
        }
    }
}
