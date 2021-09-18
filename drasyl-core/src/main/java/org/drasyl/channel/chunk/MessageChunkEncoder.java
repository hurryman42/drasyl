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
package org.drasyl.channel.chunk;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

/**
 * Encodes {@link MessageChunk}s to {@link ByteBuf}s.
 *
 * @see ChunkedMessageInput
 */
@Sharable
public final class MessageChunkEncoder extends MessageToByteEncoder<MessageChunk> {
    public static final MessageChunkEncoder INSTANCE = new MessageChunkEncoder();
    public static final int MAGIC_NUMBER_CONTENT = -143_591_473;
    public static final int MAGIC_NUMBER_LAST = -143_591_472;
    // magic number: 4 bytes
    // id: 1 byte
    // chunk number (content) / total chunks (last content): 1 byte
    // content: n bytes
    public static final int MIN_MESSAGE_LENGTH = 6;

    private MessageChunkEncoder() {
        // singleton
    }

    @Override
    protected void encode(final ChannelHandlerContext ctx,
                          final MessageChunk msg,
                          final ByteBuf out) {
        if (msg instanceof LastMessageChunk) {
            out.writeInt(MAGIC_NUMBER_LAST);
        }
        else {
            out.writeInt(MAGIC_NUMBER_CONTENT);
        }
        out.writeByte(msg.msgId());
        out.writeByte(msg.chunkNo());
        out.writeBytes(msg.content());
    }
}
