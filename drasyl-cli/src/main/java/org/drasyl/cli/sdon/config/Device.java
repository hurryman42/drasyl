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
import org.drasyl.identity.DrasylAddress;
import org.drasyl.identity.IdentityPublicKey;
import org.luaj.vm2.LuaTable;
import org.luaj.vm2.LuaValue;
import org.luaj.vm2.lib.TwoArgFunction;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Represents a device (a node or a sub-controller).
 */
public class Device extends LuaTable {
    Device(final DrasylAddress address, final DrasylAddress controllerAddress) {
        set("address", LuaValue.valueOf(address.toString()));
        set("online", FALSE);
        set("facts", tableOf());
        set("policies", tableOf());
        set("is_sub_controller", FALSE);
        set("controller_address", LuaValue.valueOf(controllerAddress.toString()));
    }

    Device(final DrasylAddress address) {
        set("address", LuaValue.valueOf(address.toString()));
        set("online", FALSE);
        set("facts", tableOf());
        set("policies", tableOf());
        set("is_sub_controller", FALSE);
        set("controller_address", LuaValue.valueOf(""));
        set("make_sub_controller", new MakeSubControllerFunction());
    }

    @Override
    public String toString() {
        final LuaTable stringTable = tableOf();
        stringTable.set("address", get("address"));
        stringTable.set("online", get("online"));
        stringTable.set("facts", get("facts"));
        stringTable.set("policies", get("policies"));
        stringTable.set("is_sub_controller", get("is_sub_controller"));
        stringTable.set("controllerAddress", get("controllerAddress"));
        return "Device" + LuaHelper.toString(stringTable);
    }

    public void setOnline() {
        set("online", TRUE);
    }

    public void setOffline() {
        set("online", FALSE);
    }

    public boolean isOnline() {
        return get("online") == TRUE;
    }

    public boolean isOffline() {
        return get("online") == FALSE;
    }

    public DrasylAddress address() {
        return IdentityPublicKey.of(get("address").tojstring());
    }

    public DrasylAddress controllerAddress() {
        return IdentityPublicKey.of(get("controllerAddress").tojstring());
    }

    public void setFacts(final Map<String, Object> facts) {
        set("facts", LuaHelper.createTable(facts));
    }

    public void setPolicies(final Set<Policy> policies) {
        final LuaTable table = tableOf();
        int index = 1;
        for (final Policy policy : policies) {
            table.set(index++, policy.luaValue());
        }
        set("policies", table);
    }

    public Set<Policy> createPolicies(String subnet) {
        final Set<Policy> policies = new HashSet<>();
        if (get("make_sub_controller") == TRUE) {
            final Policy controllerPolicy = new ControllerPolicy(address(), controllerAddress(), isSubController(), subnet);
            policies.add(controllerPolicy);
        }
        return policies;
    }

    public void setControllerAddress(final DrasylAddress controllerAddress) {
        set("controllerAddress", controllerAddress.toString());
    }

    public void setSubController() {
        set("is_sub_controller", TRUE);
    }

    public void setNotSubController() {
        set("is_sub_controller", FALSE);
    }

    public boolean isSubController() {
        return get("is_sub_controller") == TRUE;
    }

    static class MakeSubControllerFunction extends TwoArgFunction {
        @Override
        public LuaValue call(final LuaValue subControllerArg, final LuaValue devicesArg) {
            //TODO: initiate the certificate process for the sub-controller
            return NIL;
        }
    }
}
