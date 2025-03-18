math = require("math")

HIGH_WATERMARK = 3 -- maximum number of devices the primary controller can manage; at HIGH_WATERMARK+1 --> offload devices onto a new sub-controller
LOW_WATERMARK = 1 -- minimum number of devices the primary controller should have after offloading (just_starting prevents chaos at the beginning); at LOW_WATERMARK-1 --> decommission a sub-controller
-- relation ship between HIGH_WATERMARK & LOW_WATERMARK has to be:
--      HIGH_WATERMARK >= LOW_WATERMARK
--      LOW_WATERMARK > 0
SUB_CONTROLLER_HIGH_WATERMARK = 3 -- maximum number of devices a sub-controller can manage; at SUB_CONTROLLER_HIGH_WATERMARK+1 --> don't assign more devices to this sub-controller
-- the handing back of devices from an (overloaded) sub-controller is set by the maxDevices variable in SubControllerPolicyHandler, which is currently quite useless, but is there to offer future work ;)

-- in the naming scheme, "we" are the top-level controller of this network
-- if the controller of the device is the top-level controller ("us"), then the device.controllerAddress = ""

local our_devices = {} -- unordered list of all our devices
local controller_of_devices = {} -- mapping of device to its controller
local just_starting = true -- boolean to make sure the controller does not try to decommission a sub_controller when there was one created (probably a better way to do this for multiple sub_controllers)

net = create_network()
--net:add_node("n1", {ip="10.1.0.1/24", run="python3 web-server.py"})
net:add_node("n1", {ip="10.1.0.1/24"})
net:add_node("n2", {ip="10.2.0.2/24"})
net:add_node("n3", {ip="10.3.0.3/24"})
net:add_node("n4", {ip="10.3.0.4/24"})
net:add_node("n5", {ip="10.3.0.5/24"})
net:add_node("n6", {ip="10.3.0.6/24"})
net:add_node("n7", {ip="10.3.0.7/24"})
net:add_node("n8", {ip="10.3.0.8/24"})
net:add_node("n9", {ip="10.3.0.9/24"})

net:set_callback(
    function(my_net, devices) -- set_callback is called every 5000ms
        our_devices = {}
        nr_sub_controllers = 0
        --print("callback started!") --DEBUG printing
        --print(inspect(devices)) -- DEBUG printing
        --print("inspected devices") -- DEBUG printing
        print("--------------------") -- DEBUG printing

        -- sort devices in the local variables
        for id, device in pairs(devices) do
            --print("in loop of devices") -- DEBUG printing
            --print(inspect(device)) -- DEBUG printing
            --print("device.controllerAddress: " .. device.controller_address) -- DEBUG printing
            --print("device.is_sub_controller: " .. tostring(device.is_sub_controller)) -- DEBUG printing
            if device.is_sub_controller == true then -- device is sub-controller
                nr_sub_controllers = nr_sub_controllers + 1
                table.insert(our_devices, device)
                controller_of_devices[device] = "" -- TODO: this won't work for a sub_controller of a sub_controller, but for that we would need to know "our" address

                -- check if sub_controller has too many devices & remove them then (from sub_controller & add them to our_devices)
                needs = device:get_sub_controller_needs()
                device_count = device:count_my_devices()
                print(device.address .. " manages " .. tostring(device_count) .. " and can handle " .. tostring(needs) .. " more devices.")
                if needs < 0 then
                    new_devices = device:remove_devices(needs * -1)
                    print("handing back: " .. inspect(new_devices))
                    for id, device in pairs(new_devices) do
                        table.insert(our_devices, device)
                    end
                end
            elseif device.controller_address ~= "" then -- device controlled by sub-controller
                controller_of_devices[device] = device.controller_address
            elseif device.controller_address == "" then -- device controlled by "us" (top-level controller)
                table.insert(our_devices, device)
                controller_of_devices[device] = ""
            end
            -- isn't it always "controller_of_devices[device] = device.controller_address" (with a special case for "us" as controller)
        end

        -- remove deregistered devices & old sub_controllers from controller_of_devices
        for device, controller in pairs(controller_of_devices) do
            found = false
            for i, dev in ipairs(our_devices) do
                if dev.address == device.address then -- compare by address because the device object has changed
                    found = true
                end
            end
            if found == false and controller == "" then -- deregistered device
                controller_of_devices[device] = nil
            elseif found == true and controller ~= "" then -- old sub_controller
                controller_of_devices[device] = nil
            end
        end

        -- just a lot of DEBUG printing
        print("--------------------") -- DEBUG printing
        --for i, device in ipairs(our_devices) do print(inspect(device)) end -- DEBUG printing
        device_count = 0
        if next(our_devices) == nil then
            print("no devices registered (yet)") -- DEBUG printing
        else
            for device, controller in pairs(controller_of_devices) do
                device_count = device_count + 1
                if controller ~= nil then
                    if controller == "" then
                        if device.is_sub_controller == true then
                            print(device.address .. " is sub-controller with " .. device:count_my_devices() .. " devices.") -- DEBUG printing
                        else
                            print(device.address .. " has standard controller.") -- DEBUG printing
                        end
                    else
                        --print(inspect(device) .. " has controller: " .. inspect(controller))
                        print(device.address .. " has controller: " .. controller.address) -- DEBUG printing
                    end
                end
            end
        end
        print("--------------------") -- DEBUG printing
        print(#our_devices .. " = " .. (#our_devices - nr_sub_controllers) .. " devices + " .. nr_sub_controllers .. " sub-controllers") -- DEBUG printing
        print("just_starting = " .. tostring(just_starting)) -- DEBUG printing

        -- set high watermarks according to the number of devices totally connected
        HIGH_WATERMARK = set_high_watermark(device_count)
        SUB_CONTROLLER_HIGH_WATERMARK = HIGH_WATERMARK - 1
        print("HIGH_WATERMARK=" .. tostring(HIGH_WATERMARK)) -- DEBUG printing


        -- if-clause for whether to offload (CASE 1), decommission (CASE 2) or just smile and wave (CASE 3)
        if #our_devices > HIGH_WATERMARK then
            -- CASE 1: offload devices to new or existing sub-controller
            just_starting = false

            print("controller is preparing to offload...") -- DEBUG printing
            print("--------------------") -- DEBUG printing

            -- elect sub-controller (or take an existing one)
            sub_controller_capacity = SUB_CONTROLLER_HIGH_WATERMARK
            sub_controller = nil
            if nr_sub_controllers > 0 then
                -- go through all devices and check at every sub_controller if it can take anymore devices
                for id, device in pairs(devices) do
                    sub_controller_capacity = SUB_CONTROLLER_HIGH_WATERMARK -- reset this for every device inspected
                    device_count = device:count_my_devices()
                    --print(device_count) -- DEBUG printing
                    if (device.is_sub_controller == true) and (device_count < SUB_CONTROLLER_HIGH_WATERMARK) then
                        sub_controller = device
                        sub_controller_capacity = sub_controller_capacity - device_count
                        print("existing sub_controller: " .. sub_controller.address .. " with capacity: " .. tostring(sub_controller_capacity)) -- DEBUG printing
                    end
                end
            end
            if sub_controller == nil then
               -- select first device that is not already a sub_controller to become one
               i = 1
               while our_devices[i].is_sub_controller == true do
                   i = i + 1
               end
               sub_controller = our_devices[i]
               --table.remove(our_devices, i) -- sub_controller is still part of our_devices
               --sub_controller = elect_sub_controller(devices) -- this java function needs a good score to be calculated
               nr_sub_controllers = nr_sub_controllers + 1
            end
            sub_controller_capacity = SUB_CONTROLLER_HIGH_WATERMARK - sub_controller:count_my_devices() -- has to be recalculated because it could have been overwritten by later inspected sub_controllers
            print("selected sub_controller: " .. sub_controller.address .. " with capacity: " .. tostring(sub_controller_capacity)) -- DEBUG printing

            -- select devices to be offloaded (for now just take random devices (the first that are/will not be sub_controller))
            devices_to_handover = {}
            -- offload as many devices as the sub_controller can handle or as many as there are that aren't sub_controllers themself but also make sure that there will be at least LOW_WATERMARK many devices left
            --print(math.min(sub_controller_capacity, (#our_devices - nr_sub_controllers), (#our_devices - LOW_WATERMARK)))
            for counter = 1, math.min(sub_controller_capacity, (#our_devices - nr_sub_controllers), (#our_devices - LOW_WATERMARK)) do
                index = 1
                while (our_devices[index].is_sub_controller) == true or (our_devices[index] == sub_controller) do
                    index = index + 1
                end
                --devices_to_handover[our_devices[index].address] = our_devices[index] -- fill devices_to_handover in the (key-value) hash part of the LuaTable
                table.insert(devices_to_handover, our_devices[index]) -- fill devices_to_handover in the (iterable) array part of the LuaTable
                controller_of_devices[our_devices[index]] = sub_controller
                our_devices[index].controller_address = sub_controller
                table.remove(our_devices, index)
            end
            -- devices_to_handover = select_devices_to_handover(devices, #our_devices - (LOW_WATERMARK + 1))

            -- DEBUG printing
            print("--------------------") -- DEBUG printing
            for id, device in pairs(devices_to_handover) do print("device to handover: " .. device.address) end -- DEBUG printing
            for i, device in ipairs(our_devices) do print("remaining our_device: " .. device.address) end -- DEBUG printing

            -- make the LuaTable to a Devices object
            devices_to_handover = create_devices(devices_to_handover)

            -- DEBUG printing
            print("--------------------") -- DEBUG printing
            print("controller is offloading...") -- DEBUG printing
            print("--------------------") -- DEBUG printing

            -- offload devices_to_handover to sub_controller; if the device sub_controller is no sub_controller yet, the function make_sub_controller converts it to one
            sub_controller:make_sub_controller(devices_to_handover)


        elseif (#our_devices < LOW_WATERMARK) and (just_starting == false) then
            -- CASE 2: no sub-controller needed anymore, decommission it: (sub-)controller removes policies (stops sending them) --> devices go back to standard behaviour of trying to register at the top-level controller
            print("decommissioning a sub-controller") -- DEBUG printing
            print("--------------------") -- DEBUG printing
            -- for the understanding: this script is run by a controller which can only see its sub-controllers & what devices they have to manage; it cannot see HOW this sub-controller manages its devices (sub-sub-controller)

            -- count sub-controllers & how many devices they have to manage
            sub_controllers_device_count = {}
            for id, device in pairs(devices) do
                if device.is_sub_controller == true then
                    sub_controller = device
                    i = 0
                    for device, controller in pairs(controller_of_devices) do
                        if controller == sub_controller then
                            i = i + 1
                        end
                    end
                    sub_controllers_device_count[sub_controller] = i
                end
            end
            for device, amount in pairs(sub_controllers_device_count) do print(device.address .. " is a sub-controller & has " .. amount .. " devices to manage.") end -- DEBUG printing

            -- decommission sub-controllers until the #our_devices is above the LOW_WATERMARK
            while #our_devices < LOW_WATERMARK do
                -- find the sub_controller with the fewest devices to manage
                lowest_amount = 9223372036854775807 -- infinity
                for device, amount in pairs(sub_controllers_device_count) do
                    if amount <= lowest_amount then
                        sub_controller = device
                        lowest_amount = amount
                    end
                end
                print("decommissioning sub-controller " .. sub_controller.address) -- DEBUG printing
                new_devices = sub_controller:decommission_sub_controller()
                nr_sub_controllers = nr_sub_controllers - 1

                -- add the sub_controller & their devices to our_devices
                table.insert(our_devices, sub_controller)
                for id, device in pairs(new_devices) do
                    table.insert(our_devices, device)
                end
                print("--------------------") -- DEBUG printing
            end

            if #our_devices > LOW_WATERMARK then
                just_starting = true
            end
        else
            -- CASE 3: do nothing (just smile and wave)
            print("smile and wave") -- DEBUG printing
            print("--------------------") -- DEBUG printing
        end
    end
)

register_network(net)
