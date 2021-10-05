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
package org.drasyl.handler.remote;

import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.ReferenceCounted;
import org.drasyl.channel.AddressedMessage;
import org.drasyl.handler.remote.protocol.AcknowledgementMessage;
import org.drasyl.handler.remote.protocol.FullReadMessage;
import org.drasyl.handler.remote.protocol.HopCount;
import org.drasyl.handler.remote.protocol.Nonce;
import org.drasyl.handler.remote.protocol.RemoteMessage;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.identity.ProofOfWork;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import test.util.IdentityTestUtil;

import static org.drasyl.handler.remote.protocol.HopCount.MAX_HOP_COUNT;
import static org.drasyl.handler.remote.protocol.Nonce.randomNonce;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

@ExtendWith(MockitoExtension.class)
class HopCountGuardTest {
    private IdentityPublicKey senderPublicKey;
    private IdentityPublicKey recipientPublicKey;
    private Nonce correspondingId;

    @BeforeEach
    void setUp() {
        senderPublicKey = IdentityTestUtil.ID_1.getIdentityPublicKey();
        recipientPublicKey = IdentityTestUtil.ID_2.getIdentityPublicKey();
        correspondingId = Nonce.of("ea0f284eef1567c505b126671f4293924b81b4b9d20a2be7");
    }

    @Test
    void shouldPassMessagesThatHaveNotReachedTheirHopCountLimitAndIncrementHopCount(@Mock final IdentityPublicKey recipient) {
        final ChannelHandler handler = new HopCountGuard((byte) 2);
        final FullReadMessage<AcknowledgementMessage> message = AcknowledgementMessage.of(1337, recipientPublicKey, senderPublicKey, ProofOfWork.of(1), correspondingId, System.currentTimeMillis());

        final EmbeddedChannel channel = new EmbeddedChannel(handler);
        try {
            channel.writeAndFlush(new AddressedMessage<>(message, recipient));

            final ReferenceCounted actual = channel.readOutbound();
            assertEquals(new AddressedMessage<>(message.incrementHopCount(), recipient), actual);

            actual.release();
        }
        finally {
            channel.close();
        }
    }

    @Test
    void shouldDiscardMessagesThatHaveReachedTheirHopCountLimit() {
        final ChannelHandler handler = new HopCountGuard((byte) 1);
        final RemoteMessage message = AcknowledgementMessage.of(HopCount.of(MAX_HOP_COUNT), false, 0, randomNonce(), recipientPublicKey, senderPublicKey, ProofOfWork.of(1), correspondingId, System.currentTimeMillis());

        final EmbeddedChannel channel = new EmbeddedChannel(handler);
        try {
            final ChannelPromise promise = channel.newPromise();
            channel.writeAndFlush(new AddressedMessage<>(message, message.getSender()), promise);
            assertFalse(promise.isSuccess());

            assertNull(channel.readOutbound());
        }
        finally {
            channel.close();
        }
    }
}