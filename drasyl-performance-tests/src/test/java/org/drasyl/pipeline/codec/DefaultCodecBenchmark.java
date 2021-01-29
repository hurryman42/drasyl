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
package org.drasyl.pipeline.codec;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.ByteBufOutputStream;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.Unpooled;
import org.drasyl.DrasylConfig;
import org.drasyl.crypto.CryptoException;
import org.drasyl.event.Event;
import org.drasyl.identity.CompressedPublicKey;
import org.drasyl.identity.Identity;
import org.drasyl.peer.PeersManager;
import org.drasyl.pipeline.Handler;
import org.drasyl.pipeline.HandlerContext;
import org.drasyl.pipeline.Pipeline;
import org.drasyl.pipeline.address.Address;
import org.drasyl.pipeline.message.ApplicationMessage;
import org.drasyl.util.JSONUtil;
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
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

@State(Scope.Benchmark)
@Fork(value = 1)
@Warmup(iterations = 3)
@Measurement(iterations = 3)
public class DefaultCodecBenchmark {
    private final HandlerContext ctx;
    private final String msg;
    private ApplicationMessage msgEncoded;
    private CompressedPublicKey sender;
    private CompressedPublicKey recipient;

    public DefaultCodecBenchmark() {
        ctx = new MyHandlerContext();
        final byte[] bytes = new byte[1024];
        new Random().nextBytes(bytes);
        msg = new String(bytes);
        try {
            sender = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");
            recipient = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
            msgEncoded = new ApplicationMessage(sender, recipient, msg.getClass(), JSONUtil.JACKSON_WRITER.writeValueAsBytes(msg));
        }
        catch (final JsonProcessingException | CryptoException e) {
            e.printStackTrace();
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public void encode() {
        DefaultCodec.INSTANCE.encode(ctx, recipient, msg, msgEncoded -> {
        });
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public void decode() {
        DefaultCodec.INSTANCE.decode(ctx, sender, msgEncoded, (sender, msg) -> {
        });
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public void pureJacksonEncode() {
        final ByteBuf buf = PooledByteBufAllocator.DEFAULT.buffer();
        try (final ByteBufOutputStream bos = new ByteBufOutputStream(buf)) {
            JSONUtil.JACKSON_WRITER.writeValue((OutputStream) bos, msg);
        }
        catch (final IOException e) {
            e.printStackTrace();
        }
        finally {
            buf.release();
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public void pureJacksonDecode() {
        final ByteBuf buf = Unpooled.wrappedBuffer(msgEncoded.getContent());
        try (final ByteBufInputStream bis = new ByteBufInputStream(buf)) {
            JSONUtil.JACKSON_READER.readValue((InputStream) bis, msgEncoded.getTypeClazz());
        }
        catch (final IOException | IllegalArgumentException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        finally {
            buf.release();
        }
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
            return TypeValidator.ofInboundValidator(DrasylConfig.newBuilder().build());
        }

        @Override
        public TypeValidator outboundValidator() {
            return TypeValidator.ofOutboundValidator(DrasylConfig.newBuilder().build());
        }
    }
}