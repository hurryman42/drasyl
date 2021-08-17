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
package org.drasyl.remote.protocol;

import com.google.auto.value.AutoValue;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.identity.ProofOfWork;
import org.drasyl.remote.handler.crypto.AgreementId;
import org.drasyl.remote.protocol.Protocol.Acknowledgement;
import org.drasyl.remote.protocol.Protocol.PrivateHeader;

import java.io.IOException;
import java.io.OutputStream;

import static org.drasyl.remote.protocol.Nonce.randomNonce;
import static org.drasyl.remote.protocol.Protocol.MessageType.ACKNOWLEDGEMENT;

/**
 * Acknowledges a {@link DiscoveryMessage}.
 */
@AutoValue
@SuppressWarnings("java:S118")
public abstract class AcknowledgementMessage extends AbstractFullReadMessage<AcknowledgementMessage> {
    /**
     * Returns the {@link Nonce} to which this message corresponds.
     *
     * @return the {@link Nonce} to which this message corresponds
     */
    public abstract Nonce getCorrespondingId();

    @Override
    public AcknowledgementMessage incrementHopCount() {
        return AcknowledgementMessage.of(getNonce(), getNetworkId(), getSender(), getProofOfWork(), getRecipient(), getHopCount().increment(), getAgreementId(), getCorrespondingId());
    }

    @Override
    public AcknowledgementMessage setAgreementId(final AgreementId agreementId) {
        return AcknowledgementMessage.of(getNonce(), getNetworkId(), getSender(), getProofOfWork(), getRecipient(), getHopCount(), agreementId, getCorrespondingId());
    }

    @Override
    protected void writePrivateHeaderTo(final OutputStream out) throws IOException {
        PrivateHeader.newBuilder()
                .setType(ACKNOWLEDGEMENT)
                .build()
                .writeDelimitedTo(out);
    }

    @Override
    protected void writeBodyTo(final OutputStream out) throws IOException {
        Acknowledgement.newBuilder()
                .setCorrespondingId(getCorrespondingId().toByteString())
                .build()
                .writeDelimitedTo(out);
    }

    /**
     * Creates new acknowledgement message.
     *
     * @param nonce           the nonce
     * @param networkId       the network id
     * @param sender          the public key of the sender
     * @param proofOfWork     the proof of work of {@code sender}
     * @param recipient       the public key of the recipient
     * @param hopCount        the hop count
     * @param agreementId     the agreement id
     * @param correspondingId the {@link Nonce} to which this message corresponds
     * @throws NullPointerException if {@code nonce},  {@code sender}, {@code proofOfWork}, {@code
     *                              recipient}, {@code hopCount}, or {@code correspondingId} is
     *                              {@code null}
     */
    @SuppressWarnings("java:S107")
    public static AcknowledgementMessage of(final Nonce nonce,
                                            final int networkId,
                                            final IdentityPublicKey sender,
                                            final ProofOfWork proofOfWork,
                                            final IdentityPublicKey recipient,
                                            final HopCount hopCount,
                                            final AgreementId agreementId,
                                            final Nonce correspondingId) {
        return new AutoValue_AcknowledgementMessage(
                nonce,
                networkId,
                sender,
                proofOfWork,
                hopCount,
                agreementId,
                recipient,
                correspondingId
        );
    }

    /**
     * Creates new acknowledgement message with random {@link Nonce}, minimal {@link HopCount}
     * value, and no {@link AgreementId}.
     *
     * @param networkId       the network id
     * @param sender          the public key of the sender
     * @param proofOfWork     the proof of work of {@code sender}
     * @param recipient       the public key of the recipient
     * @param correspondingId the {@link Nonce} to which this message corresponds
     * @throws NullPointerException if {@code sender}, {@code proofOfWork}, {@code recipient}, or
     *                              {@code correspondingId} is {@code null}
     */
    public static AcknowledgementMessage of(final int networkId,
                                            final IdentityPublicKey sender,
                                            final ProofOfWork proofOfWork,
                                            final IdentityPublicKey recipient,
                                            final Nonce correspondingId) {
        return of(
                randomNonce(),
                networkId,
                sender,
                proofOfWork,
                recipient,
                HopCount.of(),
                null,
                correspondingId
        );
    }

    /**
     * Creates new acknowledgement message.
     *
     * @param nonce       the nonce
     * @param networkId   the network id
     * @param sender      the public key of the sender
     * @param proofOfWork the proof of work of {@code sender}
     * @param recipient   the public key of the recipient
     * @param hopCount    the hop count
     * @param agreementId the agreement id
     * @throws NullPointerException if {@code nonce},  {@code sender}, {@code proofOfWork}, {@code
     *                              recipient}, {@code hopCount}, {@code body}, or {@code
     *                              body.getCorrespondingId()} is {@code null}
     */
    @SuppressWarnings("java:S107")
    static AcknowledgementMessage of(final Nonce nonce,
                                     final int networkId,
                                     final IdentityPublicKey sender,
                                     final ProofOfWork proofOfWork,
                                     final IdentityPublicKey recipient,
                                     final HopCount hopCount,
                                     final AgreementId agreementId,
                                     final Acknowledgement body) {
        return of(
                nonce,
                networkId,
                sender,
                proofOfWork,
                recipient,
                hopCount,
                agreementId,
                Nonce.of(body.getCorrespondingId())
        );
    }
}
