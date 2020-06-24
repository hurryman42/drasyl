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
package org.drasyl.peer.connection.handler.stream;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.util.ReferenceCountUtil;
import org.drasyl.identity.CompressedPublicKey;
import org.drasyl.peer.connection.handler.SimpleChannelDuplexHandler;
import org.drasyl.peer.connection.message.ApplicationMessage;
import org.drasyl.peer.connection.message.ChunkedMessage;
import org.drasyl.peer.connection.message.StatusMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.HashMap;

/**
 * This handler allows you to send messages that are too large for the underlying WebSocket
 * transport layer. To do this, this handler splits the message into a series of non-overlapping
 * chunks.
 */
public class ChunkedMessageHandler extends SimpleChannelDuplexHandler<ChunkedMessage, ApplicationMessage> {
    private static final Logger LOG = LoggerFactory.getLogger(ChunkedMessageHandler.class);
    public static final String CHUNK_HANDLER = "chunkHandler";
    public static final int CHUNK_SIZE = 32768; // 32768 := 2^15 bytes for payload and 2^15 bytes for meta-data
    private final int maxContentLength;
    private final HashMap<String, ChunkedMessageOutput> chunks;
    private final CompressedPublicKey myIdentity;
    private final Duration transferTimeout;

    ChunkedMessageHandler(HashMap<String, ChunkedMessageOutput> chunks,
                          int maxContentLength,
                          CompressedPublicKey myIdentity,
                          Duration transferTimeout) {
        super(true, false, false);
        this.chunks = chunks;
        this.maxContentLength = maxContentLength;
        this.myIdentity = myIdentity;
        this.transferTimeout = transferTimeout;
    }

    public ChunkedMessageHandler(int maxContentLength,
                                 CompressedPublicKey myIdentity,
                                 Duration transferTimeout) {
        this(new HashMap<>(), maxContentLength, myIdentity, transferTimeout);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx,
                                ChunkedMessage msg) throws Exception {
        if (!msg.getRecipient().equals(myIdentity)) {
            // Only relaying...
            ReferenceCountUtil.retain(msg);
            ctx.fireChannelRead(msg);
            return;
        }

        if (msg.getChecksum() != null) {
            chunks.put(msg.getId(), new ChunkedMessageOutput(ctx, msg.getSender(),
                    msg.getRecipient(), msg.getContentLength(), msg.getChecksum(),
                    msg.getId(), maxContentLength, () -> chunks.remove(msg.getId()), transferTimeout.toMillis()));
            chunks.get(msg.getId()).addChunk(msg);
        }
        else if (chunks.containsKey(msg.getId())) {
            chunks.get(msg.getId()).addChunk(msg);
        }
        else {
            ctx.writeAndFlush(new StatusMessage(StatusMessage.Code.STATUS_BAD_REQUEST, msg.getId()));

            if (LOG.isDebugEnabled()) {
                LOG.debug("[{}]: Dropped chunked message `{}` because start chunk was not sent", ctx.channel().id().asShortText(), msg);
            }
        }
    }

    @Override
    protected void channelWrite0(ChannelHandlerContext ctx,
                                 ApplicationMessage msg, ChannelPromise promise) throws Exception {
        if (msg.getPayload().length > maxContentLength) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("[{}]: Payload is bigger than max content length. Message with id `{}` was not sent.", ctx.channel().id().asShortText(), msg.getId());
            }

            ReferenceCountUtil.release(msg);
            promise.setFailure(new IllegalArgumentException("Payload was to big."));
            return;
        }

        if (msg.getPayload().length > CHUNK_SIZE) {
            ChunkedMessageInput chunkedMessageInput = new ChunkedMessageInput(msg, CHUNK_SIZE);
            ctx.writeAndFlush(chunkedMessageInput, promise);
        }
        else {
            // Skip
            ctx.write(msg, promise);
        }
    }
}
