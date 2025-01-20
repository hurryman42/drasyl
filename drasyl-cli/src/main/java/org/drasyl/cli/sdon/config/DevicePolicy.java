package org.drasyl.cli.sdon.config;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.netty.channel.ChannelPipeline;
import org.drasyl.identity.DrasylAddress;
import org.luaj.vm2.LuaString;
import org.luaj.vm2.LuaValue;

import java.util.Objects;

public class DevicePolicy extends Policy {
    private DrasylAddress address;
    private DrasylAddress controller;
    private Boolean sub_controller;

    public DevicePolicy(@JsonProperty("address") final DrasylAddress address,
                        @JsonProperty("controller") final DrasylAddress controller,
                        @JsonProperty("sub_controller") final Boolean sub_controller) {
        this.address = address;
        this.controller = controller;
        this.sub_controller = sub_controller;
    }

    @JsonGetter("address")
    public DrasylAddress address() {
        return address;
    }

    @JsonGetter("controller")
    public DrasylAddress controller()  {
        return controller;
    }

    @JsonGetter("sub_controller")
    public Boolean sub_controller() {
        return sub_controller;
    }

    @Override
    public void addPolicy(ChannelPipeline pipeline) {
        // NOOP
    }

    @Override
    public void removePolicy(ChannelPipeline pipeline) {
        // NOOP
    }

    @Override
    public LuaValue luaValue() {
        final LuaValue table = super.luaValue();
        table.set("address", LuaString.valueOf(address.toString()));
        table.set("controller", LuaString.valueOf(controller.toString()));
        table.set("sub_controller", LuaString.valueOf(sub_controller));
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
        final DevicePolicy that = (DevicePolicy) o;
        return Objects.equals(address, that.address) && Objects.equals(controller, that.controller) && Objects.equals(sub_controller, that.sub_controller);
    }

    @Override
    public int hashCode() {
        return Objects.hash(address, controller, sub_controller);
    }

    @Override
    public String toString() {
        return "DevicePolicy{" +
                "address=" + address +
                ", controller=" + controller +
                ", sub-controller" + sub_controller +
                ", state=" + state +
                '}';
    }
}
