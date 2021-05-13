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

import org.drasyl.AbstractBenchmark;
import org.drasyl.DrasylConfig;
import org.drasyl.event.Event;
import org.drasyl.identity.Identity;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.identity.ProofOfWork;
import org.drasyl.peer.PeersManager;
import org.drasyl.pipeline.Handler;
import org.drasyl.pipeline.HandlerContext;
import org.drasyl.pipeline.Pipeline;
import org.drasyl.pipeline.address.Address;
import org.drasyl.pipeline.address.InetSocketAddressWrapper;
import org.drasyl.pipeline.serialization.Serialization;
import org.drasyl.remote.handler.InternetDiscovery.Peer;
import org.drasyl.remote.protocol.Nonce;
import org.drasyl.remote.protocol.Protocol.Application;
import org.drasyl.remote.protocol.RemoteEnvelope;
import org.drasyl.util.Pair;
import org.drasyl.util.RandomUtil;
import org.drasyl.util.scheduler.DrasylScheduler;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import test.util.IdentityTestUtil;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import static java.time.Duration.ofDays;

@State(Scope.Benchmark)
public class InternetDiscoveryBenchmark extends AbstractBenchmark {
    private Map<Nonce, InternetDiscovery.Ping> openPingsCache;
    private Map<Pair<IdentityPublicKey, IdentityPublicKey>, Boolean> uniteAttemptsCache;
    private Map<IdentityPublicKey, Peer> peers;
    private Set<IdentityPublicKey> directConnectionPeers;
    private InternetDiscovery handler;
    private HandlerContext ctx;
    private Address recipient;
    private RemoteEnvelope<Application> msg;
    private CompletableFuture<Void> future;
    private Set<IdentityPublicKey> superPeers;
    private IdentityPublicKey bestSuperPeer;

    @Setup
    public void setup() {
        openPingsCache = new HashMap<>();
        uniteAttemptsCache = new HashMap<>();
        peers = new HashMap<>();
        directConnectionPeers = new HashSet<>();
        superPeers = new HashSet<>();
        handler = new InternetDiscovery(openPingsCache, uniteAttemptsCache, peers, directConnectionPeers, superPeers, bestSuperPeer);

        ctx = new MyHandlerContext();
        recipient = new MyAddress();
        final byte[] payload = RandomUtil.randomBytes(1024);
        final IdentityPublicKey recipient = IdentityPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");
        msg = RemoteEnvelope.application(1, IdentityPublicKey.of("0248b7221b49775dcae85b02fdc9df41fbed6236c72c5c0356b59961190d3f8a13"), ProofOfWork.of(16425882), IdentityPublicKey.of("0248b7221b49775dcae85b02fdc9df41fbed6236c72c5c0356b59961190d3f8a13"), byte[].class.getName(), new byte[]{});

        future = new CompletableFuture<>();

        directConnectionPeers.add(recipient);
        final Peer peer = new Peer();
        peer.inboundPingOccurred();
        peer.setAddress(new InetSocketAddressWrapper("127.0.0.1", 25527));
        peers.put(recipient, peer);
    }

    @Benchmark
    @Threads(1)
    @BenchmarkMode(Mode.Throughput)
    public void matchedWrite() {
        handler.matchedOutbound(ctx, recipient, msg, future);
    }

    private static class MyHandlerContext implements HandlerContext {
        private final DrasylConfig config;
        private final Identity identity;
        private final PeersManager peersManager;

        public MyHandlerContext() {
            config = DrasylConfig.newBuilder()
                    .remotePingTimeout(ofDays(1))
                    .remotePingCommunicationTimeout(ofDays(1))
                    .build();
            identity = IdentityTestUtil.ID_1;
            peersManager = new PeersManager(event -> {
            }, identity);
        }

        @Override
        public String name() {
            return null;
        }

        @Override
        public Handler handler() {
            return null;
        }

        @Override
        public HandlerContext passException(final Exception cause) {
            return null;
        }

        @Override
        public CompletableFuture<Void> passInbound(final Address sender,
                                                   final Object msg,
                                                   final CompletableFuture<Void> future) {
            return null;
        }

        @Override
        public CompletableFuture<Void> passEvent(final Event event,
                                                 final CompletableFuture<Void> future) {
            return null;
        }

        @Override
        public CompletableFuture<Void> passOutbound(final Address recipient,
                                                    final Object msg,
                                                    final CompletableFuture<Void> future) {
            return null;
        }

        @Override
        public DrasylConfig config() {
            return config;
        }

        @Override
        public Pipeline pipeline() {
            return null;
        }

        @Override
        public DrasylScheduler independentScheduler() {
            return null;
        }

        @Override
        public DrasylScheduler dependentScheduler() {
            return null;
        }

        @Override
        public Identity identity() {
            return identity;
        }

        @Override
        public PeersManager peersManager() {
            return peersManager;
        }

        @Override
        public Serialization inboundSerialization() {
            return null;
        }

        @Override
        public Serialization outboundSerialization() {
            return null;
        }
    }

    private static class MyAddress implements Address {
    }
}