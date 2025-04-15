MAX_DEVICE_NUMBER = 3
MIN_DEVICE_NUMBER = 1

--print("------------------------------------")
print("The sub-controller script is called!")
net = create_network()
for i = 1, MAX_DEVICE_NUMBER do -- adapt this to maximum number of connected devices (last value for i is inclusive)
    net:add_node("n" .. tostring(i), {ip="10.0.2." .. tostring(i) .. "/24"})
    --net:add_node("n" .. tostring(i), {ip="10.0.2." .. tostring(i) .. "/24", run="python3 web-client.py"})
end

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
--print("------------------------------------")
