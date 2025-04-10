math = require("math")

fixed_HIGH_WATERMARK = 5 -- maximum number of actual devices the primary controller can manage (sub-controllers not counted); at HIGH_WATERMARK+1 --> offload devices onto a new sub-controller
fixed_LOW_WATERMARK = 0 -- minimum number of actual devices the primary controller should manage (sub-controllers not counted)
HIGH_WATERMARK = 2 -- maximum number of devices the primary controller can manage; at HIGH_WATERMARK+1 --> offload devices onto a new sub-controller
LOW_WATERMARK = 1 -- minimum number of devices the primary controller should have after offloading (still_scaling_up prevents chaos at the beginning); at LOW_WATERMARK-1 --> decommission a sub-controller
-- relation ship between HIGH_WATERMARK & LOW_WATERMARK has to be:
--      HIGH_WATERMARK >= LOW_WATERMARK
--      LOW_WATERMARK > 0
SUB_CONTROLLER_HIGH_WATERMARK = 1 -- maximum number of devices a sub-controller can manage; at SUB_CONTROLLER_HIGH_WATERMARK+1 --> don't assign more devices to this sub-controller
-- the handing back of devices from an (overloaded) sub-controller is set by the maxDevices variable in SubControllerPolicyHandler, which is currently quite useless, but is there to offer future work ;)

-- in the naming scheme, "we" are the primary controller of this network; if the controller of the device is the primary controller ("us"), then the device.controllerAddress = ""

local controller_of_devices = {} -- mapping of device to its controller
local still_scaling_up = true -- boolean to make sure the controller does not try to decommission a sub_controller when there was one created (probably a better way to do this for multiple sub_controllers)

net = create_network()
--net:add_node("n1", {ip="10.0.1.1/24", run="python3 web-server.py"})
net:add_node("n1", {ip="10.0.1.1/24"})
for i = 2, 20 do -- adapt this to maximum number of connected devices (last value for i is inclusive)
    net:add_node("n" .. tostring(i), {ip="10.0.1." .. tostring(i) .. "/24"})
    --net:add_node("n" .. tostring(i), {ip="10.0.1." .. tostring(i) .. "/24", run="python3 web-client.py"})
end


net:set_callback(
    function(my_net, devices) -- set_callback is called every 5000ms
        --print("--------------------") -- DEBUG printing
        --for id, device in pairs(devices) do
        --    print(inspect(device))
        --end
        --print(count_devices(devices))
        actual_devices = create_devices({}) -- devices object with only the actual devices currently connected to the primary controller (without the sub-controllers)
        nr_sub_controllers = 0

        -- removes deregistered devices from controller_of_devices
        for device, controller in pairs(controller_of_devices) do
            found = false
            for id, dev in pairs(devices) do
                if id == device.address then -- compare by address because the device object has changed
                    found = true
                elseif dev.is_sub_controller == true then
                    --print(inspect(dev.actual_devices))
                    for nr, d in ipairs(dev.actual_devices) do
                        --print(d)
                        if d == device.address then -- compare by address because the device object has changed
                            found = true
                        end
                    end
                end
            end
            --if (found == false and controller == "") or (found == true and controller ~= "") then -- deregistered device or old sub_controller
            if (found == false) then
                controller_of_devices[device] = 0 -- not nil but still
            end
        end

        print("--------------------") -- DEBUG printing
        -- sort devices into local variables
        for id, device in pairs(devices) do
            --print("device.controllerAddress: " .. device.controller_address .. ", device.is_sub_controller: " .. tostring(device.is_sub_controller)) -- DEBUG printing
            controller_of_devices[device] = ""

            if device.is_sub_controller == true then -- device is sub-controller
                nr_sub_controllers = nr_sub_controllers + 1

                -- update the device's entry in controller_of_devices
                for nr, devAddress in ipairs(device.actual_devices) do
                    for dev, con in pairs(controller_of_devices) do
                        if dev.address == devAddress then
                            controller_of_devices[dev] = device
                        end
                    end
                end

                -- check if sub_controller has too many devices & remove them then (from sub_controller & add them to actual_devices)
                needs = device:get_sub_controller_needs()
                print(device.address .. " manages " .. tostring(device:count_my_devices()) .. " and can handle " .. tostring(needs) .. " more devices.") -- DEBUG printing
                if needs < 0 then
                    new_devices = device:remove_devices(needs * -1)
                    print("handing back: " .. inspect(new_devices))
                    for id, device in pairs(new_devices) do
                        add_device_to_devices(actual_devices, device)
                    end
                end

            elseif device.controller_address == "" then -- device controlled by primary controller
                add_device_to_devices(actual_devices, device)
            end
        end

        -- just a lot of DEBUG printing for all the devices ever registered to the primary controller
        print("--------------------") -- DEBUG printing
        device_count = 0
        if count_devices(devices) == 0 then
            print("no devices registered (yet)") -- DEBUG printing
        else
            for device, controller in pairs(controller_of_devices) do
                device_count = device_count + 1 -- TODO: maybe not be best way to count the devices?
                if controller ~= 0 then -- not nil but still
                    if controller == "" then
                        if device.is_sub_controller == true then
                            print(device.address .. " is sub-controller with " .. device:count_my_devices() .. " device(s).") -- DEBUG printing
                        else
                            print(device.address .. " has standard controller.") -- DEBUG printing
                        end
                    else
                        print(device.address .. " has controller: " .. controller.address) -- DEBUG printing
                    end
                end
            end
        end
        print("--------------------") -- DEBUG printing
        --print("still_scaling_up = " .. tostring(still_scaling_up)) -- DEBUG printing
        print(count_devices(devices) .. " = " .. count_devices(actual_devices) .. " device(s) + " .. nr_sub_controllers .. " sub-controllers") -- DEBUG printing


        -- offload everything, don't count sub-controllers mode
        SUB_CONTROLLER_HIGH_WATERMARK = fixed_HIGH_WATERMARK
        HIGH_WATERMARK = fixed_HIGH_WATERMARK + nr_sub_controllers -- the originally specified HIGH_WATERMARK should not count the sub-controllers, so we have to add them here
        LOW_WATERMARK = fixed_LOW_WATERMARK + nr_sub_controllers -- the sub-controllers should not be offloaded

        -- set HIGH_WATERMARKs according to the number of devices totally connected
        --HIGH_WATERMARK = set_high_watermark(device_count)
        ---SUB_CONTROLLER_HIGH_WATERMARK = HIGH_WATERMARK - 1

        print("HIGH_WATERMARK=" .. HIGH_WATERMARK .. "  LOW_WATERMARK=" .. LOW_WATERMARK) -- DEBUG printing


        -- if-clause for whether to offload (CASE 1), decommission (CASE 2) or just smile and wave (CASE 3)
        -- CASE 1: offload devices to new or existing sub-controller
        if count_devices(devices) > HIGH_WATERMARK then
            print("controller is preparing to offload...") -- DEBUG printing
            print("--------------------") -- DEBUG printing
            still_scaling_up = false

            -- elect sub-controller (or take an existing one)
            possible_sub_controllers = create_devices({})
            if nr_sub_controllers > 0 then
                -- go through all devices & check every sub_controller if it can take anymore devices
                found_existing_sub_controller = false
                for id, device in pairs(devices) do
                    if (device.is_sub_controller == true) and (device:count_my_devices() < SUB_CONTROLLER_HIGH_WATERMARK) then
                        add_device_to_devices(possible_sub_controllers, device)
                        found_existing_sub_controller = true
                        print("existing sub_controller: " .. device.address .. " with capacity: " .. tostring(SUB_CONTROLLER_HIGH_WATERMARK - device:count_my_devices())) -- DEBUG printing
                    end
                end
                if found_existing_sub_controller == true then
                    sub_controller = elect_sub_controller(possible_sub_controllers)
                end
            end
            if count_devices(possible_sub_controllers) == 0 then
               nr_sub_controllers = nr_sub_controllers + 1
               sub_controller = elect_sub_controller(actual_devices)
               remove_device_from_devices(actual_devices, sub_controller)
            end
            sub_controller_capacity = SUB_CONTROLLER_HIGH_WATERMARK - sub_controller:count_my_devices()
            --print("selected sub-controller: " .. sub_controller.address .. " with capacity: " .. tostring(sub_controller_capacity)) -- DEBUG printing
            --print(math.min(sub_controller_capacity, count_devices(actual_devices), (count_devices(devices) - LOW_WATERMARK)) .. " devices will be offloaded to selected sub-controller: " .. sub_controller.address .. " with capacity: " .. tostring(sub_controller_capacity)) -- DEBUG printing

            -- select devices to be offloaded (as many devices as the sub_controller can handle or as many as there are that aren't sub_controllers themself but also make sure that there will be at least LOW_WATERMARK many devices left)
            devices_to_handover = select_devices_to_handover(actual_devices, sub_controller, math.min(sub_controller_capacity, count_devices(actual_devices), (count_devices(devices) - LOW_WATERMARK)))
            for id, device in pairs(devices_to_handover) do
                print(device.address .. "will be offloaded to selected sub-controller: " .. sub_controller.address .. " with capacity: " .. tostring(sub_controller_capacity)) -- DEBUG printing
                controller_of_devices[device] = sub_controller
                remove_device_from_devices(actual_devices, device)
                remove_device_from_devices(devices, device)
            end
            for id, device in pairs(devices) do print("remaining device: " .. device.address) end -- DEBUG printing

            -- offload devices_to_handover to sub_controller; if the device sub_controller is no sub_controller yet, the function make_sub_controller converts it to one
            sub_controller:make_sub_controller(devices_to_handover)


        -- CASE 2: no sub-controller needed anymore, decommission it: (sub-)controller removes policies (stops sending them) --> devices go back to standard behaviour of trying to register at the top-level controller
        elseif (count_devices(devices) < LOW_WATERMARK) and (still_scaling_up == false) then
            print("decommissioning a sub-controller") -- DEBUG printing
            print("--------------------") -- DEBUG printing
            -- for the understanding: this script is run by a controller which can only see its sub-controllers & what devices they have to manage; it cannot see HOW this sub-controller manages its devices (sub-sub-controller)

            -- count sub-controllers & how many devices they have to manage
            sub_controllers_device_count = {}
            for id, device in pairs(devices) do
                if device.is_sub_controller == true then
                    sub_controller = device
                    i = sub_controller:count_my_devices()
                    sub_controllers_device_count[sub_controller] = i
                end
            end
            for device, amount in pairs(sub_controllers_device_count) do print(device.address .. " is a sub-controller & has " .. amount .. " devices to manage.") end -- DEBUG printing

            -- decommission sub-controllers until the number of devices is above the LOW_WATERMARK
            intendedDevices = count_devices(devices)
            while intendedDevices < LOW_WATERMARK do
                -- find the sub_controller with the fewest devices to manage; TODO: maybe implement this in Java? --> make a device object of decommissionable sub-controller and then let java decide ?
                lowest_amount = 9223372036854775807 -- infinity
                for device, amount in pairs(sub_controllers_device_count) do
                    if amount <= lowest_amount then
                        sub_controller = device
                        lowest_amount = amount
                    end
                end
                print("decommissioning sub-controller " .. sub_controller.address) -- DEBUG printing
                nr_new_devices = sub_controller:decommission_sub_controller()
                nr_sub_controllers = nr_sub_controllers - 1
                intendedDevices = intendedDevices + 1 + nr_new_devices -- for the loop
            end
            still_scaling_up = true


        -- CASE 3: do nothing (just smile and wave)
        else
            print("smile and wave") -- DEBUG printing
        end

        print("--------------------") -- DEBUG printing
    end
)

register_network(net)
