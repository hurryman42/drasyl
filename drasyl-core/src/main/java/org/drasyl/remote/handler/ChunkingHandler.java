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

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;
import com.google.protobuf.CodedOutputStream;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufOutputStream;
import io.netty.channel.ChannelHandlerContext;
import org.drasyl.DrasylConfig;
import org.drasyl.annotation.NonNull;
import org.drasyl.channel.AddressedMessage;
import org.drasyl.channel.MigrationOutboundMessage;
import org.drasyl.pipeline.address.Address;
import org.drasyl.pipeline.address.InetSocketAddressWrapper;
import org.drasyl.pipeline.skeleton.SimpleDuplexHandler;
import org.drasyl.remote.protocol.ChunkMessage;
import org.drasyl.remote.protocol.Nonce;
import org.drasyl.remote.protocol.PartialReadMessage;
import org.drasyl.remote.protocol.Protocol.PublicHeader;
import org.drasyl.remote.protocol.RemoteMessage;
import org.drasyl.util.FutureCombiner;
import org.drasyl.util.FutureUtil;
import org.drasyl.util.ReferenceCountUtil;
import org.drasyl.util.UnsignedShort;
import org.drasyl.util.Worm;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.drasyl.channel.DefaultDrasylServerChannel.CONFIG_ATTR_KEY;
import static org.drasyl.channel.DefaultDrasylServerChannel.IDENTITY_ATTR_KEY;
import static org.drasyl.remote.protocol.RemoteMessage.MAGIC_NUMBER_LENGTH;
import static org.drasyl.util.LoggingUtil.sanitizeLogArg;

/**
 * This handler is responsible for merging incoming message chunks into a single message as well as
 * splitting outgoing too large messages into chunks.
 */
@SuppressWarnings({ "java:S110" })
public class ChunkingHandler extends SimpleDuplexHandler<ChunkMessage, RemoteMessage, InetSocketAddressWrapper> {
    private static final Logger LOG = LoggerFactory.getLogger(ChunkingHandler.class);
    private final Worm<Map<Nonce, ChunksCollector>> chunksCollectors;

    public ChunkingHandler() {
        this.chunksCollectors = Worm.of();
    }

    @Override
    protected void matchedInbound(final ChannelHandlerContext ctx,
                                  final InetSocketAddressWrapper sender,
                                  final ChunkMessage msg) throws IOException {
        // message is addressed to me
        if (ctx.attr(IDENTITY_ATTR_KEY).get().getIdentityPublicKey().equals(msg.getRecipient())) {
            handleInboundChunk(ctx, sender, msg, new CompletableFuture<>());
        }
        else {
            // passthrough all messages not addressed to us
            ctx.fireChannelRead(new AddressedMessage<>((Object) msg, (Address) sender));
        }
    }

    private void handleInboundChunk(final ChannelHandlerContext ctx,
                                    final InetSocketAddressWrapper sender,
                                    final ChunkMessage chunk,
                                    final CompletableFuture<Void> future) throws IOException {
        try {
            final ChunksCollector chunksCollector = getChunksCollectors(ctx.attr(CONFIG_ATTR_KEY).get()).computeIfAbsent(chunk.getNonce(), id -> new ChunksCollector(ctx.attr(CONFIG_ATTR_KEY).get().getRemoteMessageMaxContentLength(), id));
            final RemoteMessage message = chunksCollector.addChunk(chunk);

            if (message != null) {
                // message complete, pass it inbound
                getChunksCollectors(ctx.attr(CONFIG_ATTR_KEY).get()).remove(chunk.getNonce());
                ctx.fireChannelRead(new AddressedMessage<>((Object) message, (Address) sender));
            }
            else {
                // other chunks missing, but this chunk has been processed
                future.complete(null);
            }
        }
        catch (final IllegalStateException e) {
            getChunksCollectors(ctx.attr(CONFIG_ATTR_KEY).get()).remove(chunk.getNonce());
            throw e;
        }
    }

    private Map<Nonce, ChunksCollector> getChunksCollectors(final DrasylConfig config) {
        return chunksCollectors.getOrCompute(() -> CacheBuilder.newBuilder()
                .maximumSize(1_000)
                .expireAfterWrite(config.getRemoteMessageComposedMessageTransferTimeout())
                .removalListener((RemovalListener<Nonce, ChunksCollector>) entry -> {
                    if (entry.getValue().hasChunks()) {
                        //noinspection unchecked
                        LOG.debug("Not all chunks of message `{}` were received within {}ms ({} of {} present). Message dropped.", entry::getKey, config.getRemoteMessageComposedMessageTransferTimeout()::toMillis, entry.getValue()::getPresentChunks, entry.getValue()::getTotalChunks);
                        entry.getValue().release();
                    }
                })
                .build()
                .asMap());
    }

    @SuppressWarnings("java:S112")
    @Override
    protected void matchedOutbound(final ChannelHandlerContext ctx,
                                   final InetSocketAddressWrapper recipient,
                                   final RemoteMessage msg,
                                   final CompletableFuture<Void> future) throws Exception {
        if (ctx.attr(IDENTITY_ATTR_KEY).get().getIdentityPublicKey().equals(msg.getSender())) {
            // message from us, check if we have to chunk it
            final ByteBuf messageByteBuf = ctx.alloc().ioBuffer();
            msg.writeTo(messageByteBuf);
            final int messageLength = messageByteBuf.readableBytes();
            final int messageMaxContentLength = ctx.attr(CONFIG_ATTR_KEY).get().getRemoteMessageMaxContentLength();
            if (messageMaxContentLength > 0 && messageLength > messageMaxContentLength) {
                ReferenceCountUtil.safeRelease(messageByteBuf);
                throw new Exception("The message has a size of " + messageLength + " bytes and is too large. The max. allowed size is " + messageMaxContentLength + " bytes. Message dropped.");
            }
            else if (messageLength > ctx.attr(CONFIG_ATTR_KEY).get().getRemoteMessageMtu()) {
                // message is too big, we have to chunk it
                chunkMessage(ctx, recipient, msg, future, messageByteBuf, messageLength);
            }
            else {
                ReferenceCountUtil.safeRelease(messageByteBuf);
                // message is small enough. No chunking required
                FutureCombiner.getInstance().add(FutureUtil.toFuture(ctx.writeAndFlush(new MigrationOutboundMessage<>((Object) msg, (Address) recipient)))).combine(future);
            }
        }
        else {
            // message not from us. Passthrough
            FutureCombiner.getInstance().add(FutureUtil.toFuture(ctx.writeAndFlush(new MigrationOutboundMessage<>((Object) msg, (Address) recipient)))).combine(future);
        }
    }

    @SuppressWarnings("unchecked")
    private static void chunkMessage(final ChannelHandlerContext ctx,
                                     final Address recipient,
                                     final RemoteMessage msg,
                                     final CompletableFuture<Void> future,
                                     final ByteBuf messageByteBuf,
                                     final int messageSize) throws IOException {
        try {
            // create & send chunks
            UnsignedShort chunkNo = UnsignedShort.of(0);

            final PublicHeader partialChunkHeader = PublicHeader.newBuilder()
                    .setNonce(msg.getNonce().toByteString())
                    .setSender(msg.getSender().getBytes())
                    .setRecipient(msg.getRecipient().getBytes())
                    .setHopCount(1)
                    .setTotalChunks(UnsignedShort.MAX_VALUE.getValue())
                    .buildPartial();

            final int mtu = ctx.attr(CONFIG_ATTR_KEY).get().getRemoteMessageMtu();
            final UnsignedShort totalChunks = totalChunks(messageSize, mtu, partialChunkHeader);
            LOG.debug("The message `{}` has a size of {} bytes and is therefore split into {} chunks (MTU = {}).", () -> sanitizeLogArg(msg), () -> messageSize, () -> totalChunks, () -> mtu);

            final FutureCombiner combiner = FutureCombiner.getInstance();
            final int chunkSize = getChunkSize(partialChunkHeader, mtu);

            while (messageByteBuf.readableBytes() > 0) {
                ByteBuf chunkBodyByteBuf = null;
                final ByteBuf chunkByteBuf = ctx.alloc().ioBuffer();
                try (final ByteBufOutputStream outputStream = new ByteBufOutputStream(chunkByteBuf)) {
                    RemoteMessage.MAGIC_NUMBER.writeTo(outputStream);

                    // chunk header
                    final PublicHeader chunkHeader = buildChunkHeader(totalChunks, partialChunkHeader, chunkNo);
                    chunkHeader.writeDelimitedTo(outputStream);

                    // chunk body
                    final int chunkBodyLength = Math.min(messageByteBuf.readableBytes(), chunkSize);
                    chunkBodyByteBuf = messageByteBuf.readRetainedSlice(chunkBodyLength);
                    chunkByteBuf.writeBytes(chunkBodyByteBuf);

                    // send chunk
                    final RemoteMessage chunk = PartialReadMessage.of(chunkByteBuf);

                    final CompletableFuture<Void> future1 = new CompletableFuture<>();
                    FutureCombiner.getInstance().add(FutureUtil.toFuture(ctx.writeAndFlush(new MigrationOutboundMessage<>((Object) chunk, recipient)))).combine(future1);
                    combiner.add(future1);
                }
                finally {
                    ReferenceCountUtil.safeRelease(chunkBodyByteBuf);
                }

                chunkNo = chunkNo.increment();
            }

            combiner.combine(future);
        }
        finally {
            ReferenceCountUtil.safeRelease(messageByteBuf);
        }
    }

    @NonNull
    private static PublicHeader buildChunkHeader(final UnsignedShort totalChunks,
                                                 final PublicHeader partialHeader,
                                                 final UnsignedShort chunkNo) {
        final PublicHeader.Builder builder = PublicHeader.newBuilder(partialHeader);
        builder.clearTotalChunks();

        if (chunkNo.getValue() == 0) {
            // set only on first chunk (head chunk)
            builder.setTotalChunks(totalChunks.getValue());
        }
        else {
            // set on all non-head chunks
            builder.setChunkNo(chunkNo.getValue());
        }

        return builder.build();
    }

    /**
     * Calculates how much chunks are required to send the payload of the given size with the given
     * max mtu value.
     *
     * @param payloadSize the size of the payload
     * @param mtu         the fixed mtu value
     * @param header      the header of each chunk
     * @return the total amount of chunks required to send the given payload
     */
    private static UnsignedShort totalChunks(final int payloadSize,
                                             final int mtu,
                                             final PublicHeader header) {
        final double chunkSize = getChunkSize(header, mtu);
        final int totalChunks = (int) Math.ceil(payloadSize / chunkSize);

        return UnsignedShort.of(totalChunks);
    }

    /**
     * Calculates the chunk size.
     *
     * @param header the header of each chunk
     * @param mtu    the mtu value
     * @return the size of each chunk
     */
    private static int getChunkSize(final PublicHeader header, final int mtu) {
        final int headerSize = header.getSerializedSize();

        return mtu - (MAGIC_NUMBER_LENGTH + CodedOutputStream.computeUInt32SizeNoTag(headerSize) + headerSize);
    }
}
