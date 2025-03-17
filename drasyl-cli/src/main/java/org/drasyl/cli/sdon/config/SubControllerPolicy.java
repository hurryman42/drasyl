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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.netty.channel.ChannelPipeline;
import io.netty.util.internal.StringUtil;
import org.drasyl.cli.sdon.handler.policy.SubControllerPolicyHandler;
import org.drasyl.identity.DrasylAddress;
import org.luaj.vm2.LuaString;
import org.luaj.vm2.LuaValue;

import java.util.Objects;
import java.util.Set;

public class SubControllerPolicy extends AbstractPolicy {
    public static final String HANDLER_NAME = StringUtil.simpleClassName(SubControllerPolicy.class);
    private DrasylAddress address;
    private DrasylAddress controller;
    private Set<DrasylAddress> devices;
    private Boolean is_sub_controller;
    private String subnet; // the subnet has to be a String, because a Subnet Object is not serializable (but before & after this PolicyClass it is a Subnet)
    private String myFunctionFileName;

    // TODO: add callback function from the lua-script and make sure its called periodically
    // TODO: maybe add a maximum number of devices that the sub-controller is allowed to manage? Or/and add that as a "permission" in the certificate? --> in the function of the sub-controller!

    @JsonCreator
    public SubControllerPolicy(@JsonProperty("address") final DrasylAddress address,
                               @JsonProperty("controller") final DrasylAddress controller,
                               @JsonProperty("devices") final Set<DrasylAddress> devices,
                               @JsonProperty("is_sub_controller") final Boolean isSubController,
                               @JsonProperty("subnet_string") final String subnet,
                               @JsonProperty("my_function_file_name") final String myFunctionFileName) {

        this.address = address;
        this.controller = controller;
        this.devices = devices;
        this.is_sub_controller = isSubController;
        this.subnet = subnet;
        this.myFunctionFileName = myFunctionFileName;
    }

    @JsonGetter("address")
    public DrasylAddress address() {
        return address;
    }

    @JsonGetter("controller")
    public DrasylAddress controller() {
        return controller;
    }

    @JsonGetter("devices")
    public Set<DrasylAddress> devices() {
        return devices;
    }

    @JsonGetter("is_sub_controller")
    public Boolean is_sub_controller() {
        return is_sub_controller;
    }

    @JsonGetter("subnet_string")
    public String subnetString() {
        return subnet;
    }

    @JsonGetter("my_function_file_name")
    public String myFunctionFileName() {
        return myFunctionFileName;
    }

    @Override
    public void addPolicy(final ChannelPipeline pipeline) {
        pipeline.addLast(HANDLER_NAME, new SubControllerPolicyHandler(this));
    }

    @Override
    public void removePolicy(final ChannelPipeline pipeline) {
        pipeline.remove(HANDLER_NAME);
    }

    @Override
    public LuaValue luaValue() {
        final LuaValue table = super.luaValue();
        table.set("address", LuaString.valueOf(address.toString()));
        table.set("controller", LuaString.valueOf(controller.toString()));
        table.set("is_sub_controller", LuaString.valueOf(is_sub_controller));
        table.set("subnet", LuaString.valueOf(subnet));
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
        final SubControllerPolicy that = (SubControllerPolicy) o;
        return Objects.equals(address, that.address) && Objects.equals(controller, that.controller) && Objects.equals(devices, that.devices) && Objects.equals(is_sub_controller, that.is_sub_controller) && Objects.equals(subnet, that.subnet);
    }

    @Override
    public int hashCode() {
        return Objects.hash(address, controller, devices, is_sub_controller, subnet);
    }

    @Override
    public String toString() {
        return "SubControllerPolicy{" +
                "address=" + address +
                ", controller=" + controller +
                ", devices=" + devices +
                ", is_sub_controller=" + is_sub_controller +
                ", state=" + state +
                ", subnet=" + subnet +
                ", myFunctionFileName=" + myFunctionFileName +
                '}';
    }
}
