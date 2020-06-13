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

import org.drasyl.identity.Identity;
import org.drasyl.peer.PeerInformation;
import org.drasyl.util.KeyValue;

import java.util.Set;

public class RegisterGrandchildMessage extends AbstractGrandchildMessage {
    private RegisterGrandchildMessage() {
        super();
    }

    /**
     * Creates a new register grandchild message.
     *
     * @param grandchildren        the grandchildren
     */
    public RegisterGrandchildMessage(Set<KeyValue<Identity, PeerInformation>> grandchildren) {
        super(grandchildren);
    }

    @Override
    public String toString() {
        return "RegisterGrandchildMessage{" +
                "grandchildren=" + grandchildren +
                ", id='" + id +
                '}';
    }
}
