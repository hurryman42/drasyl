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

import com.fasterxml.jackson.annotation.JsonInclude;
import org.drasyl.identity.Identity;
import org.drasyl.peer.PeerInformation;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

/**
 * A message representing the welcome message of the node server, including fallback information and
 * the public key of the node server.
 */
public class WelcomeMessage extends AbstractMessageWithUserAgent implements ResponseMessage<JoinMessage> {
    private final Identity identity;
    private final PeerInformation peerInformation;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final String correspondingId;

    protected WelcomeMessage() {
        identity = null;
        peerInformation = null;
        correspondingId = null;
    }

    /**
     * Creates new welcome message.
     *
     * @param identity        the identity of the node server
     * @param peerInformation the peer information of the node server
     * @param correspondingId
     */
    public WelcomeMessage(Identity identity,
                          PeerInformation peerInformation,
                          String correspondingId) {
        this.identity = requireNonNull(identity);
        this.peerInformation = requireNonNull(peerInformation);
        this.correspondingId = correspondingId;
    }

    public Identity getIdentity() {
        return this.identity;
    }

    public PeerInformation getPeerInformation() {
        return this.peerInformation;
    }

    @Override
    public String getCorrespondingId() {
        return correspondingId;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), identity, peerInformation, correspondingId);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        WelcomeMessage that = (WelcomeMessage) o;
        return Objects.equals(identity, that.identity) &&
                Objects.equals(peerInformation, that.peerInformation) &&
                Objects.equals(correspondingId, that.correspondingId);
    }

    @Override
    public String toString() {
        return "WelcomeMessage{" +
                "identity=" + identity +
                ", peerInformation=" + peerInformation +
                ", correspondingId='" + correspondingId + '\'' +
                ", id='" + id +
                '}';
    }
}
