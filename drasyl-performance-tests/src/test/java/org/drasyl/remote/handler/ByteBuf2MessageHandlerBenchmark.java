/*
 * Copyright (c) 2021.
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
package org.drasyl.remote.handler;

import org.drasyl.DrasylConfig;
import org.drasyl.crypto.CryptoException;
import org.drasyl.event.Event;
import org.drasyl.identity.CompressedPublicKey;
import org.drasyl.identity.Identity;
import org.drasyl.identity.ProofOfWork;
import org.drasyl.peer.PeersManager;
import org.drasyl.pipeline.Handler;
import org.drasyl.pipeline.HandlerContext;
import org.drasyl.pipeline.Pipeline;
import org.drasyl.pipeline.address.Address;
import org.drasyl.pipeline.address.InetSocketAddressWrapper;
import org.drasyl.pipeline.codec.TypeValidator;
import org.drasyl.remote.protocol.AddressedByteBuf;
import org.drasyl.remote.protocol.IntermediateEnvelope;
import org.drasyl.remote.protocol.Protocol.Application;
import org.drasyl.util.scheduler.DrasylScheduler;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

@State(Scope.Benchmark)
@Fork(value = 1)
@Warmup(iterations = 3)
@Measurement(iterations = 3)
public class ByteBuf2MessageHandlerBenchmark {
    private HandlerContext ctx;
    private Address sender;
    private AddressedByteBuf msg;
    private CompletableFuture<Void> future;

    public ByteBuf2MessageHandlerBenchmark() {
        try {
            ctx = new MyHandlerContext();
            sender = new MyAddress();
            final InetSocketAddressWrapper msgSender = InetSocketAddressWrapper.of(InetSocketAddress.createUnresolved("127.0.0.1", 25527));
            final InetSocketAddressWrapper msgRecipient = InetSocketAddressWrapper.of(InetSocketAddress.createUnresolved("127.0.0.1", 25527));
            final byte[] payload = new byte[1024];
            new Random().nextBytes(payload);
            final IntermediateEnvelope<Application> acknowledgementMessage = IntermediateEnvelope.application(1337, CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22"), ProofOfWork.of(6518542), CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4"), byte[].class.getName(), payload);
            msg = new AddressedByteBuf(msgSender, msgRecipient, acknowledgementMessage.getOrBuildByteBuf());
            future = new CompletableFuture<>();
        }
        catch (final IOException | CryptoException e) {
            e.printStackTrace();
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public void matchedRead() {
        ByteBuf2MessageHandler.INSTANCE.matchedRead(ctx, sender, msg, future);
    }

    private static class MyHandlerContext implements HandlerContext {
        @Override
        public String name() {
            return null;
        }

        @Override
        public Handler handler() {
            return null;
        }

        @Override
        public HandlerContext fireExceptionCaught(final Exception cause) {
            return null;
        }

        @Override
        public CompletableFuture<Void> fireRead(final Address sender,
                                                final Object msg,
                                                final CompletableFuture<Void> future) {
            return null;
        }

        @Override
        public CompletableFuture<Void> fireEventTriggered(final Event event,
                                                          final CompletableFuture<Void> future) {
            return null;
        }

        @Override
        public CompletableFuture<Void> write(final Address recipient,
                                             final Object msg,
                                             final CompletableFuture<Void> future) {
            return null;
        }

        @Override
        public DrasylConfig config() {
            return null;
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
            return null;
        }

        @Override
        public PeersManager peersManager() {
            return null;
        }

        @Override
        public TypeValidator inboundValidator() {
            return null;
        }

        @Override
        public TypeValidator outboundValidator() {
            return null;
        }
    }

    private static class MyAddress implements Address {
    }
}
