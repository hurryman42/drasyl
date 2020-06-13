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

import com.google.common.collect.ImmutableSet;
import org.drasyl.identity.Identity;
import org.drasyl.peer.PeerInformation;
import org.drasyl.util.KeyValue;

import java.util.Objects;
import java.util.Set;

public abstract class AbstractGrandchildMessage extends AbstractMessage implements RequestMessage {
    protected Set<KeyValue<Identity, PeerInformation>> grandchildren;

    protected AbstractGrandchildMessage() {
        grandchildren = null;
    }

    public AbstractGrandchildMessage(Set<KeyValue<Identity, PeerInformation>> grandchildren) {
        this.grandchildren = grandchildren;
    }

    public Set<KeyValue<Identity, PeerInformation>> getGrandchildren() {
        return ImmutableSet.copyOf(grandchildren);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), grandchildren);
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
        AbstractGrandchildMessage that = (AbstractGrandchildMessage) o;
        return Objects.equals(grandchildren, that.grandchildren);
    }
}
