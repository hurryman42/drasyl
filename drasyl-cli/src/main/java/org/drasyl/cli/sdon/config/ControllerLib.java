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
import org.luaj.vm2.lib.TwoArgFunction;

import java.util.Collection;
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
        env.set("elect_devices_to_handover", new ElectDevicesToHandoverFunction());
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
            final Collection<Device> deviceList = devices.getDevicesCollection();
            final Device subController = deviceList.iterator().next(); // at first calculate no score, but take the first best
            /*int bestScore = 0;
            for (Device device : deviceList) {
                int currentDeviceScore = device.calculateConnectionScore(); // TODO: write function that calculates good score for the selection of sub-controller
                if (currentDeviceScore >= bestScore) {
                    bestScore = currentDeviceScore;
                    subController = device;
                }
            }*/
            return LuaValue.valueOf(subController.toString());
        }
    }

    static class ElectDevicesToHandoverFunction extends TwoArgFunction {
        @Override
        public LuaValue call(final LuaValue devicesArg, final LuaValue amountArg) {
            // just take the first best devices
            final LuaTable devicesTable = devicesArg.checktable();
            final Devices devices = (Devices) devicesTable;
            final Collection<Device> deviceList = devices.getDevicesCollection();
            final int amount = amountArg.toint();
            final Devices devicesToHandover = new Devices();
            for (Device device : deviceList) {
                devicesToHandover.add(device);
            }
            return devicesToHandover;
        }
    }
}
