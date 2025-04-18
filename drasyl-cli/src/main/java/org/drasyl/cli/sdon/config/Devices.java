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

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class Devices extends LuaTable {
    public Devices() {
        // the Devices class should not have any functions in it because than then these functions are elements in every Devices object and the Lua script cannot iterate through Devices (that easily)
    }

    public Devices(LuaTable devices) {
        for (int i = 1; i <= devices.length(); i++) {
            getOrCreateDevice(IdentityPublicKey.of(devices.get(i).tojstring()));
        }
    }

    @Override
    public String toString() {
        return "Devices" + LuaHelper.toString(this);
    }

    public Device getOrCreateDevice(final DrasylAddress address) {
        final LuaValue device = get(address.toString());
        if (device != NIL) {
            return (Device) device;
        }
        else {
            final Device newDevice = new Device(address);
            set(address.toString(), newDevice);
            return newDevice;
        }
    }

    public Device getOrCreateDevice(final DrasylAddress address, final DrasylAddress controller) {
        final LuaValue device = get(address.toString());
        if (device != NIL) {
            return (Device) device;
        }
        else {
            final Device newDevice = new Device(address, controller);
            set(address.toString(), newDevice);
            return newDevice;
        }
    }

    public Collection<Device> getDevices() {
        final Set<Device> devices = new HashSet<>();
        final LuaValue[] keys = keys();
        for (final LuaValue key : keys) {
            if (get(key) != NIL) {
                devices.add((Device) get(key));
            }
        }
        return devices;
    }

    public Set<DrasylAddress> getDeviceAddresses() {
        final Set<DrasylAddress> deviceAddresses = new HashSet<>();
        final LuaValue[] keys = keys();
        for (final LuaValue key : keys) {
            if (get(key) != NIL) {
                final Device device = (Device) get(key);
                deviceAddresses.add(device.address());
            }
        }
        return deviceAddresses;
    }

    public void addDevice(final Device device) {
        set(device.address().toString(), device);
    }

    public void removeDevice(final Device device) {
        set(device.address().toString(), NIL);
    }

    public int countDevices() {
        final LuaValue[] keys = keys();
        return keys.length;
    }

    public boolean isEmpty() {
        return countDevices() == 0;
    }
}
