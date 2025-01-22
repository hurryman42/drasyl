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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonSubTypes.Type;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import io.netty.util.internal.StringUtil;
import org.luaj.vm2.LuaString;
import org.luaj.vm2.LuaTable;
import org.luaj.vm2.LuaValue;

import static org.drasyl.cli.sdon.config.AbstractPolicy.PolicyState.FAILED;
import static org.drasyl.cli.sdon.config.AbstractPolicy.PolicyState.PRESENT;
import static org.luaj.vm2.LuaValue.NIL;
import static org.luaj.vm2.LuaValue.tableOf;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
@JsonSubTypes({
        @Type(TunPolicy.class),
        @Type(LinkPolicy.class),
})
abstract class AbstractPolicy implements Policy {
    protected PolicyState state;

    protected AbstractPolicy(final PolicyState state) {
        this.state = state;
    }

    protected AbstractPolicy() {
        this(null);
    }

    @JsonIgnore
    @Override
    public void setPresent() {
        if (state != null) {
            throw new IllegalStateException("Policy state is already set.");
        }
        this.state = PRESENT;
    }

    @JsonIgnore
    @Override
    public void setFailed() {
        if (state != null) {
            throw new IllegalStateException("Policy state is already set.");
        }
        this.state = FAILED;
    }

    @Override
    public LuaValue luaValue() {
        final LuaTable table = tableOf();
        table.set("type", StringUtil.simpleClassName(this));
        table.set("state", state != null ? LuaString.valueOf(state.toString()) : NIL);
        return table;
    }

    public enum PolicyState {
        PRESENT, FAILED
    }
}
