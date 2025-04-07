/*
 * Copyright (c) 2020-2025 Heiko Bornholdt and Kevin Röbert
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

import org.drasyl.util.Worm;
import org.luaj.vm2.LuaError;
import org.luaj.vm2.LuaTable;
import org.luaj.vm2.LuaValue;
import org.luaj.vm2.lib.OneArgFunction;
import org.luaj.vm2.lib.ThreeArgFunction;
import org.luaj.vm2.lib.TwoArgFunction;
import org.luaj.vm2.lib.VarArgFunction;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Lua API provided by the controller.
 */
@SuppressWarnings({ "java:S110", "java:S2160" })
public class ControllerLib extends TwoArgFunction {
    public final Worm<Network> network;

    public ControllerLib(final Worm<Network> network) {
        this.network = requireNonNull(network);
    }

    @Override
    public LuaValue call(final LuaValue modname, final LuaValue env) {
        final LuaValue library = tableOf();
        env.set("create_network", new CreateNetworkFunction());
        env.set("register_network", new RegisterNetworkFunction(network));
        env.set("inspect", new InspectFunction());
        env.set("get_network", new GetNetworkFunction());
        env.set("elect_sub_controller", new ElectSubControllerFunction());
        env.set("select_devices_to_handover", new SelectDevicesToHandoverFunction());
        env.set("create_devices", new CreateDevicesFunction());
        env.set("add_device_to_devices", new AddDeviceToDevicesFunction());
        env.set("remove_device_from_devices", new RemoveDeviceFromDevicesFunction());
        env.set("count_devices", new CountDevicesFunction());
        env.set("set_high_watermark", new SetHighWatermarkFunction());
        return library;
    }

    @SuppressWarnings("java:S110")
    static class CreateNetworkFunction extends OneArgFunction {
        @Override
        public LuaValue call(final LuaValue paramsArg) {
            return new Network(paramsArg);
        }
    }

    @SuppressWarnings({ "java:S110", "java:S2160" })
    static class RegisterNetworkFunction extends OneArgFunction {
        private final Worm<Network> network;

        public RegisterNetworkFunction(final Worm<Network> network) {
            this.network = requireNonNull(network);
        }

        @Override
        public LuaValue call(final LuaValue networkArg) {
            final LuaTable networkTable = networkArg.checktable();

            if (network.isPresent()) {
                throw new LuaError("Only one network can be registered.");
            }

            network.set((Network) networkTable);

            return NIL;
        }
    }

    static class InspectFunction extends OneArgFunction {
        @Override
        public LuaValue call(final LuaValue arg) {
            return LuaValue.valueOf(arg.toString());
        }
    }

    static class GetNetworkFunction extends OneArgFunction {
        @Override
        public LuaTable call(final LuaValue deviceArg) {
            return new LuaTable();
        }
    }

    static class ElectSubControllerFunction extends OneArgFunction {
        @Override
        public LuaValue call(final LuaValue devicesArg) {
            final LuaTable devicesTable = devicesArg.checktable();
            final Devices devices = (Devices) devicesTable;
            final Set<Device> deviceSet = (Set<Device>) devices.getDevices();
            final ArrayList<Device> deviceList = new ArrayList<>(deviceSet);

            deviceList.sort(Comparator.comparing(dev -> dev.address().toString())); // sorts devices alphabetically
            /*int bestScore = 0;
            for (Device device : deviceSet) {
                // TODO: write function that calculates good score for the selection of sub-controller
                int currentDeviceScore = device.calculateConnectionScore();
                if (currentDeviceScore >= bestScore) {
                    bestScore = currentDeviceScore;
                    subController = device;
                }
            }*/
            return deviceList.iterator().next();
        }
    }

    static class SelectDevicesToHandoverFunction extends ThreeArgFunction {
        @Override
        public LuaValue call(final LuaValue devicesArg, final LuaValue subControllerArg, final LuaValue amountArg) {
            final LuaTable devicesTable = devicesArg.checktable();
            final Devices devices = (Devices) devicesTable;

            final LuaTable subControllerTable = subControllerArg.checktable();
            final Device subController = (Device) subControllerTable;

            devices.removeDevice(subController);
            final Set<Device> deviceSet = (Set<Device>) devices.getDevices();
            final ArrayList<Device> deviceList = new ArrayList<>(deviceSet);

            // sort the deviceList alphabetically by addresses
            deviceList.sort(Comparator.comparing(dev -> dev.address().toString())); // sorts devices alphabetically

            final int amount = amountArg.toint();
            final Devices devicesToHandover = new Devices();
            for (int i = 0; i < amount; i++) {
                final Device device = deviceList.get(i);
                device.setControllerAddress(subController.address());
                devicesToHandover.addDevice(device);
            }

            return devicesToHandover;
        }
    }

    /**
     * Converts a LuaTable with Device objects in its array list part into a Devices object and returns it
     */
    static class CreateDevicesFunction extends VarArgFunction {
        @Override
        public Devices call(final LuaValue devicesArg) {
            final Devices devices = new Devices();
            final LuaTable devicesTable = devicesArg.checktable();
            // TODO: check first, whether the array or the hash part (or both) of the LuaTable is filled
            for (int i = 1; i <= devicesTable.length(); i++) {
                try {
                    final Device device = (Device) devicesTable.get(i);
                    devices.addDevice(device);
                }
                catch (Exception e) {
                    System.out.println("Element of Table was not of type Device.");
                }
            }
            return devices;
        }
    }

    static class AddDeviceToDevicesFunction extends TwoArgFunction {
        @Override
        public LuaValue call(final LuaValue devicesArg, final LuaValue deviceArg) {
            final Devices devices = (Devices) devicesArg.checktable();
            final Device device = (Device) deviceArg.checktable();

            devices.addDevice(device);

            return NIL;
        }
    }

    static class RemoveDeviceFromDevicesFunction extends TwoArgFunction {
        @Override
        public LuaValue call(final LuaValue devicesArg, final LuaValue deviceArg) {
            final Devices devices = (Devices) devicesArg.checktable();
            final Device device = (Device) deviceArg.checktable();

            devices.removeDevice(device);

            return NIL;
        }
    }

    static class CountDevicesFunction extends OneArgFunction {
        @Override
        public LuaValue call(final LuaValue devicesArg) {
            final Devices devices = (Devices) devicesArg.checktable();
            return LuaValue.valueOf(devices.countDevices());
        }
    }

    static class SetHighWatermarkFunction extends OneArgFunction {
        @Override
        public LuaValue call(final LuaValue deviceCount) {
            int device_count = deviceCount.toint();
            return LuaValue.valueOf((int) Math.ceil(Math.sqrt(device_count)));
        }
    }
}
