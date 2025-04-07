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
import org.luaj.vm2.LuaInteger;
import org.luaj.vm2.LuaTable;
import org.luaj.vm2.LuaValue;
import org.luaj.vm2.lib.OneArgFunction;
import org.luaj.vm2.lib.TwoArgFunction;

import java.util.Collection;
import java.util.HashMap;
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
        set("intended_devices", tableOf());
        set("actual_devices", tableOf());
        set("controller_address", LuaValue.valueOf(controllerAddress.toString()));
        set("make_sub_controller", new MakeSubControllerFunction());
        set("decommission_sub_controller", new DecommissionSubControllerFunction());
        set("remove_devices", new RemoveDevicesFromSubControllerFunction());
        set("set_my_function", new SetFunction());
        set("get_sub_controller_needs", new GetSubControllerDeviceNeeds());
        set("count_my_devices", new CountMyDevicesFunction());
    }

    public Device(final DrasylAddress address) {
        set("address", LuaValue.valueOf(address.toString()));
        set("online", FALSE);
        set("facts", tableOf());
        set("policies", tableOf());
        set("is_sub_controller", FALSE);
        set("intended_devices", tableOf());
        set("actual_devices", tableOf());
        set("controller_address", LuaValue.valueOf(""));
        set("make_sub_controller", new MakeSubControllerFunction());
        set("decommission_sub_controller", new DecommissionSubControllerFunction());
        set("remove_devices", new RemoveDevicesFromSubControllerFunction());
        set("set_my_function", new SetFunction());
        set("get_sub_controller_needs", new GetSubControllerDeviceNeeds());
        set("count_my_devices", new CountMyDevicesFunction());
    }

    @Override
    public String toString() {
        final LuaTable stringTable = tableOf();
        stringTable.set("address", get("address"));
        stringTable.set("online", get("online"));
        stringTable.set("facts", get("facts"));
        stringTable.set("policies", get("policies"));
        stringTable.set("is_sub_controller", get("is_sub_controller"));
        stringTable.set("intended_devices", get("intended_devices"));
        stringTable.set("actual_devices", get("actual_devices"));
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

    public Devices intendedDevices() {
        return new Devices(get("intended_devices").checktable());
    }

    public Devices actualDevices() {
        return new Devices(get("actual_devices").checktable());
    }

    public void setFacts(final Map<String, Object> facts) {
        //System.out.println(facts);
        final LuaTable table = LuaHelper.createTable(facts);
        set("facts", table);
    }

    public Map<String, Object> getFacts() {
        final Map<String, Object> factsMap = new HashMap<>();
        final LuaTable factsTable = get("facts").checktable();
        for (LuaValue key : factsTable.keys()) {
            factsMap.put(key.tojstring(), factsTable.get(key));
        }
        return factsMap;
    }

    public void setPolicies(final Set<Policy> policies) {
        final LuaTable table = tableOf();
        int index = 1;
        for (final Policy policy : policies) {
            table.set(index++, policy.luaValue());

            // update the devices in the device object based on feedback from the sub-controller
            if (policy instanceof SubControllerPolicy) {
                final LuaTable devAddresses = tableOf();
                final Set<DrasylAddress> addresses = ((SubControllerPolicy) policy).devices();
                int i = devAddresses.length() + 1;
                for (DrasylAddress address : addresses) {
                    devAddresses.set(i++, LuaValue.valueOf(address.toString()));
                }
                set("actual_devices", devAddresses);
            }
        }
        set("policies", table);
    }

    public Set<Policy> createPolicies(Subnet subnet, String fallbackControllerAddress) {
        final Set<Policy> policies = new HashSet<>();

        if (isSubController()) { // the SDON controller always sends SubControllerPolicies to a sub-controller with no difference whether the controller is already instantiated (the device/sub-controller checks that)
            final Devices myDevices = new Devices(get("intended_devices").checktable());
            final Set<DrasylAddress> myDeviceAddresses = myDevices.getDeviceAddresses();
            if (isOnline()) { // this check is probably not necessary, but it won't hurt either, right?
                final Policy controllerPolicy = new SubControllerPolicy(address(), controllerAddress(fallbackControllerAddress), myDeviceAddresses, true, subnet.toString(), "sub-controller-conf.lua");
                policies.add(controllerPolicy);
            }
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

    public void addIntendedDevices(Devices devices) {
        final LuaTable devAddresses = get("intended_devices").checktable();
        //final LuaTable devAddresses = new LuaTable();
        final Collection<Device> devs = devices.getDevices();
        int index = devAddresses.length() + 1;
        for (Device dev : devs) {
            devAddresses.insert(index++, LuaValue.valueOf(dev.address().toString()));
        }
        set("intended_devices", devAddresses);
    }

    public void addActualDevices(Devices devices) {
        final LuaTable devAddresses = get("actual_devices").checktable();
        //final LuaTable devAddresses = new LuaTable();
        final Collection<Device> devs = devices.getDevices();
        int index = devAddresses.length() + 1;
        for (Device dev : devs) {
            devAddresses.insert(index++, LuaValue.valueOf(dev.address().toString()));
        }
        set("actual_devices", devAddresses);
    }

    public void removeAllIntendedDevices() {
        set("intended_devices", new LuaTable());
    }

    public void removeAllActualDevices() {
        set("actual_devices", new LuaTable());
    }

    void setFunction(final LuaFunction function) {
        this.myFunction = function;
        //return (LuaNil) NIL;
    }

    static class MakeSubControllerFunction extends TwoArgFunction {
        @Override
        public LuaValue call(final LuaValue subControllerArg, final LuaValue devicesArg) {
            final LuaTable devTable = devicesArg.checktable();
            final LuaTable subControllerTable = subControllerArg.checktable();
            try {
                final Device subController = (Device) subControllerTable;
                final Devices newDevices = (Devices) devTable;
                if (!subController.isSubController()) {
                    subController.setSubController();
                }
                subController.addIntendedDevices(newDevices);
            }
            catch (ClassCastException e) {
                System.out.println("The given LuaTables are not of Device & Devices type, instead " + subControllerTable.getClass() + " & " + devTable.getClass());
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
                if (subController.isOnline()) {
                    subController.setNotSubController();
                    final int nrReturnedDevices = subController.intendedDevices().countDevices();
                    subController.removeAllIntendedDevices();
                    return LuaValue.valueOf(nrReturnedDevices);
                }
                else {
                    final int nrReturnedDevices = subController.intendedDevices().countDevices();
                    return LuaValue.valueOf(nrReturnedDevices);
                }
            }
            catch (ClassCastException e) {
                System.out.println("The given LuaTable is not of Device type, instead " + subControllerTable.getClass());
            }
            return LuaValue.valueOf(0);
        }
    }

    static class RemoveDevicesFromSubControllerFunction extends TwoArgFunction {
        @Override
        public LuaValue call(final LuaValue subControllerArg, final LuaValue amountArg) {
            final LuaTable subControllerTable = subControllerArg.checktable();
            final int amountDevices = amountArg.checkinteger().toint();
            try {
                final Device subController = (Device) subControllerTable;
                final Devices subControllerDevices = subController.intendedDevices();
                final Set<Device> subControllerDeviceSet = (Set<Device>) subControllerDevices.getDevices();
                final Devices returnedDevices = new Devices();
                // removes (amountDevices often) the first device from the sub-controller's devices & adds it to the returnedDevices
                for (int i = 0; i < amountDevices; i++) {
                    final Device device = subControllerDeviceSet.iterator().next();
                    returnedDevices.addDevice(device);
                    subControllerDeviceSet.remove(device);
                    subControllerDevices.removeDevice(device);
                }
                subController.addIntendedDevices(subControllerDevices);
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

    static class GetSubControllerDeviceNeeds extends OneArgFunction {
        @Override
        public LuaValue call(final LuaValue subControllerArg) {
            final LuaTable subControllerTable = subControllerArg.checktable();
            try {
                final Device subController = (Device) subControllerTable;
                final Map<String, Object> theFacts = subController.getFacts();
                if (theFacts.containsKey("max_devices")) {
                    final LuaInteger luaInt = (LuaInteger) subController.getFacts().get("max_devices");
                    final int maxDevices = luaInt.checkint();
                    final int currentDevices = subController.actualDevices().getDevices().size();
                    return LuaValue.valueOf(maxDevices - currentDevices);
                }
                else {
                    return LuaValue.valueOf(0);
                }
            }
            catch (ClassCastException e) {
                System.out.println("The given LuaTable is not of Device type, instead " + subControllerTable.getClass());
            }
            return NIL;
        }
    }

    static class CountMyDevicesFunction extends OneArgFunction {
        @Override
        public LuaValue call(final LuaValue deviceArg) {
            final Device device = (Device) deviceArg.checktable();
            return LuaValue.valueOf(device.actualDevices().countDevices());
        }
    }
}
