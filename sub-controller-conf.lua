print("------------------------------------")
print("The sub-controller script is called!")
net = create_network()
net:add_node("n1", {ip="10.0.1.42/24"})

MAX_DEVICE_NUMBER = 2
net:set_callback(
    function(my_net, devices)
        print("callback called")
        --if #devices > MAX_DEVICE_NUMBER and just_starting == true then
        --    just_starting = false -- delays handing back the device by one "iteration" (5s)
        --elseif #devices > MAX_DEVICE_NUMBER and just_starting == false then
        --    -- give device back to controller
        --    -- easy: give device to top-level controller
        --    sub_controller:remove_devices(1) -- TODO: how to get sub_controller?
        --    -- harder: give device to the sub-controller's controller
        --end
    end
)

register_network(net)
print("------------------------------------")
