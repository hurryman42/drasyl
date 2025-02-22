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
import org.drasyl.util.network.Subnet;
import org.luaj.vm2.LuaFunction;
import org.luaj.vm2.LuaNil;
import org.luaj.vm2.LuaTable;
import org.luaj.vm2.LuaValue;
import org.luaj.vm2.lib.OneArgFunction;
import org.luaj.vm2.lib.TwoArgFunction;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Represents a device (a node or a sub-controller).
 */
public class Device extends LuaTable {
    LuaFunction myFunction;

    public Device(final DrasylAddress address, final DrasylAddress controllerAddress) {
        set("address", LuaValue.valueOf(address.toString()));
        set("online", FALSE);
        set("facts", tableOf());
        set("policies", tableOf());
        set("is_sub_controller", FALSE);
        set("my_devices", tableOf());
        set("controller_address", LuaValue.valueOf(controllerAddress.toString()));
        set("make_sub_controller", new MakeSubControllerFunction());
        set("decommission_sub_controller", new DecommissionSubControllerFunction());
        set("set_my_function", new Device.SetFunction());
    }

    public Device(final DrasylAddress address) {
        set("address", LuaValue.valueOf(address.toString()));
        set("online", FALSE);
        set("facts", tableOf());
        set("policies", tableOf());
        set("is_sub_controller", FALSE);
        set("my_devices", tableOf());
        set("controller_address", LuaValue.valueOf(""));
        set("make_sub_controller", new MakeSubControllerFunction());
        set("decommission_sub_controller", new DecommissionSubControllerFunction());
        set("set_my_function", new Device.SetFunction());
    }

    @Override
    public String toString() {
        final LuaTable stringTable = tableOf();
        stringTable.set("address", get("address"));
        stringTable.set("online", get("online"));
        stringTable.set("facts", get("facts"));
        stringTable.set("policies", get("policies"));
        stringTable.set("is_sub_controller", get("is_sub_controller"));
        stringTable.set("my_devices", get("my_devices"));
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

    public DrasylAddress controllerAddress(String fallbackControllerAddress) {
        final String controllerAddressString = get("controllerAddress").tojstring();
        if (controllerAddressString.isEmpty() || "nil".equals(controllerAddressString)) {
            return IdentityPublicKey.of(fallbackControllerAddress);
        }
        else {
            return IdentityPublicKey.of(controllerAddressString);
        }
    }

    public Devices myDevices() {
        return new Devices(get("my_devices").checktable());
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

    public Set<Policy> createPolicies(Subnet subnet, String fallbackControllerAddress) {
        final Set<Policy> policies = new HashSet<>();
        if (isSubController()) { // the SDON controller always sends SubControllerPolicies to a sub-controller with no difference whether the controller is already instantiated (the device (sub-controller) checks that)
            final Devices myDevices = new Devices(get("my_devices").checktable());
            final Collection<Device> myDeviceCollection = myDevices.getDevices();
            final Set<DrasylAddress> myDeviceAddresses = new HashSet<>();
            for (Device device : myDeviceCollection) {
                myDeviceAddresses.add(device.address());
            }
            //final boolean testIsSubController = isSubController();
            final Policy controllerPolicy = new SubControllerPolicy(address(), controllerAddress(fallbackControllerAddress), myDeviceAddresses, true, subnet.toString(), "sub-controller-conf.lua");
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
        return (get("is_sub_controller") == TRUE);
    }

    public void setDevices(Devices devices) {
        final LuaTable devAddresses = new LuaTable();
        final Collection<Device> devs = devices.getDevices();
        int index = 0;
        for (Device dev : devs) {
            devAddresses.insert(index++, LuaValue.valueOf(dev.address().toString()));
        }
        set("my_devices", devAddresses);
    }

    public void removeAllDevices() {
        set("my_devices", new LuaTable());
    }

    LuaNil setFunction(final LuaFunction function) {
        this.myFunction = function;

        return (LuaNil) NIL;
    }

    static class MakeSubControllerFunction extends TwoArgFunction {
        @Override
        public LuaValue call(final LuaValue subControllerArg, final LuaValue devicesArg) {
            final LuaTable devTable = devicesArg.checktable();
            final LuaTable subControllerTable = subControllerArg.checktable();
            try {
                final Device subController = (Device) subControllerTable;
                final Devices myDevices = (Devices) devTable;
                subController.setSubController();
                subController.setDevices(myDevices);
            }
            catch (ClassCastException e) {
                System.out.println("The given LuaTables are not of Device and Devices type, instead " + subControllerTable.getClass() + "and" + devTable.getClass());
            }
            return NIL;
        }
    }

    static class DecommissionSubControllerFunction extends OneArgFunction {
        @Override
        public LuaValue call(final LuaValue subControllerArg) {
            final LuaTable subControllerTable = subControllerArg.checktable();
            try {
                final Device subController = (Device) subControllerTable;
                subController.setNotSubController();
                final Devices returnedDevices = subController.myDevices();
                subController.removeAllDevices();
                return returnedDevices;
            }
            catch (ClassCastException e) {
                System.out.println("The given LuaTable is not of Device type, instead " + subControllerTable.getClass());
            }
            return NIL;
        }
    }

    static class SetFunction extends TwoArgFunction {
        @Override
        public LuaValue call(final LuaValue deviceArg, final LuaValue functionArg) {
            final Device device = (Device) deviceArg.checktable();
            final LuaFunction function = functionArg.checkfunction();

            device.setFunction(function);

            return NIL;
        }
    }
}
