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
package org.drasyl.peer.connection.message;

import org.drasyl.DrasylNode;
import org.drasyl.identity.CompressedPublicKey;
import org.drasyl.identity.ProofOfWork;

import java.util.Objects;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;
import static org.drasyl.peer.connection.message.MessageId.randomMessageId;

/**
 * Message that represents a message from one node to another one.
 */
@SuppressWarnings({ "squid:S1444", "squid:ClassVariableVisibilityCheck" })
abstract class AbstractMessage implements Message {
    public static final Supplier<String> defaultUserAgentGenerator = () -> "drasyl/" + DrasylNode.getVersion() + " (" + System.getProperty("os.name") + "; "
            + System.getProperty("os.arch") + "; Java/"
            + System.getProperty("java.vm.specification.version") + ":" + System.getProperty("java.version.date")
            + ")";
    public static Supplier<String> userAgentGenerator = defaultUserAgentGenerator;
    protected final MessageId id;
    protected final UserAgent userAgent;
    protected final int networkId;
    protected final CompressedPublicKey sender;
    protected final ProofOfWork proofOfWork;
    protected final CompressedPublicKey recipient;
    protected short hopCount;

    /**
     * @param id          message's identifier
     * @param userAgent   message's user agent
     * @param networkId   message's network
     * @param sender      message's sender
     * @param proofOfWork sender's proof of work
     * @param recipient   message'srecipient
     * @param hopCount    message's hop count
     * @throws IllegalArgumentException if hopCount is negative
     */
    protected AbstractMessage(final MessageId id,
                              final UserAgent userAgent,
                              final int networkId,
                              final CompressedPublicKey sender,
                              final ProofOfWork proofOfWork,
                              final CompressedPublicKey recipient,
                              final short hopCount) {
        this.id = requireNonNull(id);
        this.userAgent = requireNonNull(userAgent);
        this.networkId = networkId;
        this.sender = requireNonNull(sender);
        this.proofOfWork = requireNonNull(proofOfWork);
        this.recipient = requireNonNull(recipient);
        if (hopCount < 0) {
            throw new IllegalArgumentException("hopCount must not be negative.");
        }
        this.hopCount = hopCount;
    }

    protected AbstractMessage(final int networkId,
                              final CompressedPublicKey sender,
                              final ProofOfWork proofOfWork,
                              final CompressedPublicKey recipient,
                              final short hopCount) {
        this(randomMessageId(), UserAgent.generate(), networkId, sender, proofOfWork, recipient, hopCount);
    }

    protected AbstractMessage(final int networkId,
                              final CompressedPublicKey sender,
                              final ProofOfWork proofOfWork,
                              final CompressedPublicKey recipient) {
        this(networkId, sender, proofOfWork, recipient, (short) 0);
    }

    public AbstractMessage(final MessageId id,
                           final int networkId,
                           final CompressedPublicKey sender,
                           final ProofOfWork proofOfWork,
                           final CompressedPublicKey recipient,
                           final short hopCount) {
        this(id, UserAgent.generate(), networkId, sender, proofOfWork, recipient, hopCount);
    }

    @Override
    public MessageId getId() {
        return id;
    }

    @Override
    public UserAgent getUserAgent() {
        return userAgent;
    }

    @Override
    public int getNetworkId() {
        return networkId;
    }

    @Override
    public CompressedPublicKey getSender() {
        return sender;
    }

    @Override
    public ProofOfWork getProofOfWork() {
        return proofOfWork;
    }

    @Override
    public CompressedPublicKey getRecipient() {
        return recipient;
    }

    @Override
    public short getHopCount() {
        return hopCount;
    }

    @Override
    public void incrementHopCount() {
        hopCount++;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final AbstractMessage that = (AbstractMessage) o;
        return networkId == that.networkId &&
                Objects.equals(sender, that.sender) &&
                Objects.equals(proofOfWork, that.proofOfWork) &&
                Objects.equals(recipient, that.recipient);
    }

    @Override
    public int hashCode() {
        return Objects.hash(networkId, sender, proofOfWork, recipient, hopCount);
    }
}