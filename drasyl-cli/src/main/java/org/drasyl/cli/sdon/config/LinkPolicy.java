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
package org.drasyl.cli.sdon.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.netty.channel.ChannelPipeline;
import org.drasyl.identity.DrasylAddress;
import org.luaj.vm2.LuaString;
import org.luaj.vm2.LuaValue;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

/**
 * Policy for a link to another device.
 */
public class LinkPolicy extends AbstractPolicy {
    private final String peer;
    private final DrasylAddress peerAddress;

    @JsonCreator
    public LinkPolicy(@JsonProperty("peer") final String peer,
                      @JsonProperty("peerAddress") final DrasylAddress peerAddress) {
        super();
        this.peer = requireNonNull(peer);
        this.peerAddress = requireNonNull(peerAddress);
    }

    @JsonGetter("peer")
    public String peer() {
        return peer;
    }

    @JsonGetter("peerAddress")
    public DrasylAddress peerAddress() {
        return peerAddress;
    }

    public void addPolicy(final ChannelPipeline pipeline) {
        // NOOP
    }

    @Override
    public void removePolicy(final ChannelPipeline pipeline) {
        // NOOP
    }

    @Override
    public LuaValue luaValue() {
        final LuaValue table = super.luaValue();
        table.set("peer", LuaString.valueOf(peer));
        table.set("peerAddress", LuaString.valueOf(peerAddress.toString()));
        return table;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final LinkPolicy that = (LinkPolicy) o;
        return Objects.equals(peer, that.peer) && Objects.equals(peerAddress, that.peerAddress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(peer, peerAddress);
    }

    @Override
    public String toString() {
        return "LinkPolicy{" +
                "peer=" + peer +
                ", peerAddress=" + peerAddress +
                ", state=" + state +
                '}';
    }
}
