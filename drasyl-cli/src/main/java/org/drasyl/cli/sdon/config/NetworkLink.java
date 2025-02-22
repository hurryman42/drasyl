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

import org.drasyl.cli.util.LuaHelper;
import org.luaj.vm2.LuaString;
import org.luaj.vm2.LuaTable;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

/**
 * Represents a network link.
 */
public class NetworkLink extends LuaTable {
    private final Network network;

    NetworkLink(final Network network,
                final LuaString node1,
                final LuaString node2,
                final LuaTable params) {
        this.network = requireNonNull(network);
        set("node1", node1);
        set("node2", node2);
    }

    @Override
    public String toString() {
        return "Link" + LuaHelper.toString(this);
    }

    public LuaString node1() {
        return (LuaString) get("node1");
    }

    public LuaString node2() {
        return (LuaString) get("node2");
    }

    public LuaString other(final LuaString name) {
        if (node1().equals(name)) {
            return node2();
        }
        else {
            return node1();
        }
    }

    @Override
    public int hashCode() {
        if (node1().hashCode() > node2().hashCode()) {
            return Objects.hash(node1(), node2());
        }
        else {
            return Objects.hash(node2(), node1());
        }
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final NetworkLink that = (NetworkLink) o;
        return (Objects.equals(node1(), that.node1()) && Objects.equals(node2(), that.node2())) || (Objects.equals(node1(), that.node2()) && Objects.equals(node2(), that.node1()));
    }
}
