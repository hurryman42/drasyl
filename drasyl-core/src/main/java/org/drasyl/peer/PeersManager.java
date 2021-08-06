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
package org.drasyl.peer;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;
import org.drasyl.channel.MigrationEvent;
import org.drasyl.channel.MigrationHandlerContext;
import org.drasyl.event.Node;
import org.drasyl.event.NodeOfflineEvent;
import org.drasyl.event.NodeOnlineEvent;
import org.drasyl.event.Peer;
import org.drasyl.event.PeerDirectEvent;
import org.drasyl.event.PeerRelayEvent;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.util.SetUtil;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static java.util.Objects.requireNonNull;
import static org.drasyl.channel.DefaultDrasylServerChannel.IDENTITY_ATTR_KEY;

/**
 * This class contains information about other peers. This includes the public keys, available
 * interfaces, connections or relations (e.g. direct/relayed connection, super peer, child). Before
 * a relation is set for a peer, it must be ensured that its information is available. Likewise, the
 * information may not be removed from a peer if the peer still has a relation
 *
 * <p>
 * This class is optimized for concurrent access and is thread-safe.
 * </p>
 */
public class PeersManager {
    private final ReadWriteLock lock;
    private final SetMultimap<IdentityPublicKey, Object> paths;
    private final Set<IdentityPublicKey> children;
    private final Set<IdentityPublicKey> superPeers;

    public PeersManager() {
        this(new ReentrantReadWriteLock(true), HashMultimap.create(), new HashSet<>(), new HashSet<>());
    }

    @SuppressWarnings("java:S2384")
    PeersManager(final ReadWriteLock lock,
                 final SetMultimap<IdentityPublicKey, Object> paths,
                 final Set<IdentityPublicKey> children,
                 final Set<IdentityPublicKey> superPeers) {
        this.lock = lock;
        this.paths = paths;
        this.children = children;
        this.superPeers = superPeers;
    }

    @Override
    public String toString() {
        try {
            lock.readLock().lock();

            return "PeersManager{" +
                    ", paths=" + paths +
                    ", children=" + children +
                    ", superPeers=" + superPeers +
                    '}';
        }
        finally {
            lock.readLock().unlock();
        }
    }

    public Set<IdentityPublicKey> getPeers() {
        try {
            lock.readLock().lock();

            return SetUtil.merge(paths.keySet(), SetUtil.merge(superPeers, children));
        }
        finally {
            lock.readLock().unlock();
        }
    }

    public Set<IdentityPublicKey> getChildren() {
        try {
            lock.readLock().lock();

            // It is necessary to create a new HashMap because otherwise, this can raise a
            // ConcurrentModificationException.
            // See: https://git.informatik.uni-hamburg.de/sane-public/drasyl/-/issues/77
            return Set.copyOf(children);
        }
        finally {
            lock.readLock().unlock();
        }
    }

    public Set<IdentityPublicKey> getSuperPeers() {
        try {
            lock.readLock().lock();

            // It is necessary to create a new HashMap because otherwise, this can raise a
            // ConcurrentModificationException.
            // See: https://git.informatik.uni-hamburg.de/sane-public/drasyl/-/issues/77
            return Set.copyOf(superPeers);
        }
        finally {
            lock.readLock().unlock();
        }
    }

    public Set<Object> getPaths(final IdentityPublicKey publicKey) {
        requireNonNull(publicKey);

        try {
            lock.readLock().lock();

            return Set.copyOf(paths.get(publicKey));
        }
        finally {
            lock.readLock().unlock();
        }
    }

    public void addPath(final MigrationHandlerContext ctx,
                        final IdentityPublicKey publicKey,
                        final Object path) {
        requireNonNull(publicKey);

        try {
            lock.writeLock().lock();

            final boolean firstPath = paths.get(publicKey).isEmpty();
            if (paths.put(publicKey, path) && firstPath) {
                ctx.fireUserEventTriggered(new MigrationEvent(PeerDirectEvent.of(Peer.of(publicKey)), new CompletableFuture<Void>()));
            }
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    public void removePath(final MigrationHandlerContext ctx,
                           final IdentityPublicKey publicKey,
                           final Object path) {
        requireNonNull(publicKey);
        requireNonNull(path);

        try {
            lock.writeLock().lock();

            if (paths.remove(publicKey, path) && paths.get(publicKey).isEmpty()) {
                ctx.fireUserEventTriggered(new MigrationEvent(PeerRelayEvent.of(Peer.of(publicKey)), new CompletableFuture<Void>()));
            }
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    public void addPathAndSuperPeer(final MigrationHandlerContext ctx,
                                    final IdentityPublicKey publicKey,
                                    final Object path) {
        requireNonNull(publicKey);
        requireNonNull(path);

        try {
            lock.writeLock().lock();

            // path
            final boolean firstPath = paths.get(publicKey).isEmpty();
            if (paths.put(publicKey, path) && firstPath) {
                ctx.fireUserEventTriggered(new MigrationEvent(PeerDirectEvent.of(Peer.of(publicKey)), new CompletableFuture<Void>()));
            }

            // role (super peer)
            final boolean firstSuperPeer = superPeers.isEmpty();
            if (superPeers.add(publicKey) && firstSuperPeer) {
                ctx.fireUserEventTriggered(new MigrationEvent(NodeOnlineEvent.of(Node.of(ctx.attr(IDENTITY_ATTR_KEY).get())), new CompletableFuture<Void>()));
            }
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    public void removeSuperPeerAndPath(final MigrationHandlerContext ctx,
                                       final IdentityPublicKey publicKey,
                                       final Object path) {
        requireNonNull(path);

        try {
            lock.writeLock().lock();

            // role (super peer)
            if (superPeers.remove(publicKey) && superPeers.isEmpty()) {
                ctx.fireUserEventTriggered(new MigrationEvent(NodeOfflineEvent.of(Node.of(ctx.attr(IDENTITY_ATTR_KEY).get())), new CompletableFuture<Void>()));
            }

            // path
            if (paths.remove(publicKey, path) && paths.get(publicKey).isEmpty()) {
                ctx.fireUserEventTriggered(new MigrationEvent(PeerRelayEvent.of(Peer.of(publicKey)), new CompletableFuture<Void>()));
            }
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    public void addPathAndChildren(final MigrationHandlerContext ctx,
                                   final IdentityPublicKey publicKey,
                                   final Object path) {
        requireNonNull(publicKey);
        requireNonNull(path);

        try {
            lock.writeLock().lock();

            // path
            final boolean firstPath = paths.get(publicKey).isEmpty();
            if (paths.put(publicKey, path) && firstPath) {
                ctx.fireUserEventTriggered(new MigrationEvent(PeerDirectEvent.of(Peer.of(publicKey)), new CompletableFuture<Void>()));
            }

            // role (children peer)
            children.add(publicKey);
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    public void removeChildrenAndPath(final MigrationHandlerContext ctx,
                                      final IdentityPublicKey publicKey,
                                      final Object path) {
        requireNonNull(publicKey);
        requireNonNull(path);

        try {
            lock.writeLock().lock();

            // path
            if (paths.remove(publicKey, path) && paths.get(publicKey).isEmpty()) {
                ctx.fireUserEventTriggered(new MigrationEvent(PeerRelayEvent.of(Peer.of(publicKey)), new CompletableFuture<Void>()));
            }

            // role (children)
            children.remove(publicKey);
        }
        finally {
            lock.writeLock().unlock();
        }
    }
}
