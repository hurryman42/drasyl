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
package org.drasyl.handler.remote.protocol;

import com.google.auto.value.AutoValue;
import com.goterl.lazysodium.utils.SessionPair;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.Unpooled;
import org.drasyl.annotation.Nullable;
import org.drasyl.crypto.Crypto;
import org.drasyl.crypto.CryptoException;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.identity.ProofOfWork;
import org.drasyl.util.UnsignedShort;

import java.io.IOException;

/**
 * Describes an unencrypted protocol message whose only public header has been read so far.
 * <p>
 * {@link #read()} can be used to read the message's remainder.
 * <p>
 * This is an immutable object.
 */
@AutoValue
@SuppressWarnings("java:S118")
public abstract class UnarmedProtocolMessage implements PartialReadMessage {
    @Nullable
    public abstract IdentityPublicKey getRecipient();

    @Override
    public void close() {
        release();
    }

    @Override
    public int refCnt() {
        return getBytes().refCnt();
    }

    @Override
    public UnarmedProtocolMessage retain() {
        getBytes().retain();
        return this;
    }

    @Override
    public UnarmedProtocolMessage retain(final int increment) {
        getBytes().retain(increment);
        return this;
    }

    @Override
    public UnarmedProtocolMessage touch() {
        getBytes().touch();
        return this;
    }

    @Override
    public UnarmedProtocolMessage touch(final Object hint) {
        getBytes().touch(hint);
        return this;
    }

    @Override
    public boolean release() {
        return getBytes().release();
    }

    @Override
    public boolean release(final int decrement) {
        return getBytes().release(decrement);
    }

    @Override
    public UnarmedProtocolMessage incrementHopCount() {
        return UnarmedProtocolMessage.of(getHopCount().increment(), getArmed(), getNetworkId(), getNonce(), getRecipient(), getSender(), getProofOfWork(), getBytes().retain());
    }

    @Override
    public void writeTo(final ByteBuf out) {
        out.writeInt(MAGIC_NUMBER);
        buildPublicHeader().writeTo(out);
        out.writeBytes(getBytes().slice());
    }

    /**
     * Read the remainder of this message and returns the resulted {@link FullReadMessage}.
     * <p>
     * {@code getBytes()} will be consumed and released by this method.
     *
     * @return the fully read message
     * @throws InvalidMessageFormatException if message could not be read
     */
    @SuppressWarnings({ "java:S138", "java:S1142", "java:S1151", "java:S1452" })
    public FullReadMessage<?> read() throws InvalidMessageFormatException {
        try {
            final PrivateHeader privateHeader = PrivateHeader.of(getBytes());

            switch (privateHeader.getType()) {
                case ACKNOWLEDGEMENT:
                    return AcknowledgementMessage.of(
                            getHopCount(),
                            getNetworkId(),
                            getNonce(),
                            getRecipient(),
                            getSender(),
                            getProofOfWork(),
                            getBytes()
                    );
                case APPLICATION:
                    return ApplicationMessage.of(
                            getHopCount(),
                            getArmed(),
                            getNetworkId(),
                            getNonce(),
                            getRecipient(),
                            getSender(),
                            getProofOfWork(),
                            getBytes().slice().retain()
                    );
                case UNITE:
                    return UniteMessage.of(
                            getHopCount(),
                            getNetworkId(),
                            getNonce(),
                            getRecipient(),
                            getSender(),
                            getProofOfWork(),
                            getBytes()
                    );
                case DISCOVERY:
                    return DiscoveryMessage.of(
                            getHopCount(),
                            getNetworkId(),
                            getNonce(),
                            getRecipient(),
                            getSender(),
                            getProofOfWork(),
                            getBytes()
                    );
                default:
                    throw new InvalidMessageFormatException("Message is not of any known type.");
            }
        }
        finally {
            getBytes().release();
        }
    }

    private PublicHeader buildPublicHeader() {
        return PublicHeader.of(this);
    }

    /**
     * Returns an armed version ({@link ArmedProtocolMessage}) of this message.
     *
     * @param cryptoInstance the crypto instance that should be used
     * @param sessionPair    will be used for encryption
     * @return the armed version ({@link ArmedProtocolMessage}) of this message
     * @throws InvalidMessageFormatException if arming was not possible
     */
    public ArmedProtocolMessage arm(final Crypto cryptoInstance,
                                    final SessionPair sessionPair) throws InvalidMessageFormatException {
        try {
            getBytes().markReaderIndex();
            try (final ByteBufInputStream in = new ByteBufInputStream(getBytes())) {
                final UnsignedShort armedLength = PrivateHeader.getArmedLength(getBytes());
                final byte[] encryptedPrivateHeader = cryptoInstance.encrypt(in.readNBytes(PrivateHeader.LENGTH), buildAuthTag(), getNonce(), sessionPair);
                final byte[] encryptedBytes;

                if (armedLength.getValue() > 0) {
                    encryptedBytes = cryptoInstance.encrypt(in.readAllBytes(), new byte[0], getNonce(), sessionPair);
                }
                else {
                    encryptedBytes = in.readAllBytes();
                }

                return ArmedProtocolMessage.of(
                        getNonce(),
                        getHopCount(), getNetworkId(),
                        getRecipient(), getSender(),
                        getProofOfWork(),
                        Unpooled.wrappedBuffer(encryptedPrivateHeader, encryptedBytes)
                );
            }
        }
        catch (final IOException | CryptoException e) {
            throw new InvalidMessageFormatException("Unable to arm message.", e);
        }
        finally {
            getBytes().resetReaderIndex();
        }
    }

    /**
     * Returns an armed version ({@link ArmedProtocolMessage}) of this message and then releases
     * this message.
     *
     * @param cryptoInstance the crypto instance that should be used
     * @param sessionPair    will be used for encryption
     * @return the armed version ({@link ArmedProtocolMessage}) of this message
     * @throws InvalidMessageFormatException if arming was not possible
     */
    public ArmedProtocolMessage armAndRelease(final Crypto cryptoInstance,
                                              final SessionPair sessionPair) throws InvalidMessageFormatException {
        try {
            return arm(cryptoInstance, sessionPair);
        }
        finally {
            release();
        }
    }

    private byte[] buildAuthTag() {
        return buildPublicHeader().buildAuthTag();
    }

    /**
     * Creates an unarmed message.
     * <p>
     * {@link ByteBuf#release()} ownership of {@code bytes} is transferred to this {@link
     * PartialReadMessage}.
     * <p>
     * Modifying the content of {@code bytes} or the returned message's buffer affects each other's
     * content while they maintain separate indexes and marks.
     *
     * @param hopCount    the hop count
     * @param isArmed     if this message is armed or not
     * @param networkId   the network id
     * @param nonce       the nonce
     * @param recipient   the public key of the recipient
     * @param sender      the public key of the sender
     * @param proofOfWork the proof of work of {@code sender}
     * @param bytes       message's remainder as bytes (may be armed). {@link ByteBuf#release()}
     *                    ownership is transferred to this {@link PartialReadMessage}.
     * @return an {@link PartialReadMessage}
     * @throws NullPointerException if {@code nonce}, {@code sender}, {@code proofOfWork}, or {@code
     *                              recipient} is {@code null}
     */
    @SuppressWarnings("java:S107")
    public static UnarmedProtocolMessage of(final HopCount hopCount,
                                            final boolean isArmed,
                                            final int networkId,
                                            final Nonce nonce,
                                            final IdentityPublicKey recipient,
                                            final IdentityPublicKey sender,
                                            final ProofOfWork proofOfWork,
                                            final ByteBuf bytes) {
        return new AutoValue_UnarmedProtocolMessage(
                nonce,
                networkId,
                sender,
                proofOfWork,
                hopCount,
                isArmed,
                bytes,
                recipient
        );
    }
}