/*
 * Copyright (c) 2020-2024 Heiko Bornholdt and Kevin Röbert
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
package org.drasyl.handler.remote.protocol;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.UnpooledByteBufAllocator;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.identity.ProofOfWork;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.InetSocketAddress;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static test.util.IdentityTestUtil.ID_1;
import static test.util.IdentityTestUtil.ID_2;
import static test.util.IdentityTestUtil.ID_3;

@ExtendWith(MockitoExtension.class)
public class UniteMessageTest {
    private IdentityPublicKey sender;
    private ProofOfWork proofOfWork;
    private IdentityPublicKey recipient;
    private IdentityPublicKey publicKey;

    @BeforeEach
    void setUp() {
        sender = ID_1.getIdentityPublicKey();
        proofOfWork = ID_1.getProofOfWork();
        recipient = ID_2.getIdentityPublicKey();
        publicKey = ID_3.getIdentityPublicKey();
    }

    @Nested
    class GetSocketAddress {
        @Test
        void shouldReturnCorrectAddress() {
            final UniteMessage unite = UniteMessage.of(1, recipient, sender, proofOfWork, publicKey, Set.of(new InetSocketAddress(22527)));

            assertEquals(Set.of(new InetSocketAddress(22527)), unite.getEndpoints());
        }
    }

    @Nested
    class Of {
        @Test
        void shouldCreateUniteMessage() {
            final UniteMessage unite = UniteMessage.of(1, recipient, sender, proofOfWork, publicKey, Set.of(new InetSocketAddress(22527)));

            assertEquals(1, unite.getNetworkId());
            assertEquals(publicKey, unite.getAddress());
        }
    }

    @Nested
    class GetLength {
        @Test
        void shouldReturnCorrectLength() {
            final UniteMessage unite = UniteMessage.of(1, recipient, sender, proofOfWork, publicKey, Set.of(new InetSocketAddress(22527)));
            final int length = unite.getLength();

            final ByteBufAllocator alloc = UnpooledByteBufAllocator.DEFAULT;
            ByteBuf byteBuf = null;
            try {
                byteBuf = unite.encodeMessage(alloc);

                assertEquals(byteBuf.readableBytes(), length);
            }
            finally {
                if (byteBuf != null) {
                    byteBuf.release();
                }
            }
        }
    }
}
