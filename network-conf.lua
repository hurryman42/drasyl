HIGH_WATERMARK = 3 -- device count for when to offload onto a new sub-controller
LOW_WATERMARK = 1 -- device count for when to decommission a sub-controller
-- HIGH_WATERMARK & LOW_WATERMARK have to have at least a difference of 2 (otherwise the sub-controller is decommissioned & directly recreated again in an endless loop)

-- in the naming scheme, "we" are the top-level controller of this network
-- if the controller of the device is the top-level controller ("us"), then the device.controllerAddress = ""

local our_devices = {} -- unordered list of all our devices
local controller_of_devices = {} -- mapping of device to its controller
local just_starting = true -- boolean to make sure the controller does not try to decommission a sub_controller when there was one created (probably a better way to do this for multiple sub_controllers)

net = create_network()
net:add_node("n1", {ip="10.1.0.1/24"})
net:add_node("n2", {ip="10.2.0.2/24"})
net:add_node("n3", {ip="10.3.0.3/24"})

net:set_callback(
    function(my_net, devices) -- set_callback is called every 5000ms
        our_devices = {}
        nr_sub_controllers = 0
        --print("callback started!") --DEBUG printing
        --print(inspect(devices)) -- DEBUG printing
        --print("inspected devices") -- DEBUG printing

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
                print(device.address .. " can handle " .. tostring(needs) .. " more devices.")
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

        print("--------------------") -- DEBUG printing
        --for i, device in ipairs(our_devices) do print(inspect(device)) end -- DEBUG printing
        if next(our_devices) == nil then
            print("no devices registered (yet)") -- DEBUG printing
        else
            for device, controller in pairs(controller_of_devices) do
                if controller ~= nil then
                    if controller == "" then
                        --print(inspect(device) .. " has standard controller") -- DEBUG printing
                        print(device.address .. " has standard controller.") -- DEBUG printing
                    else
                        --print(inspect(device) .. " has controller: " .. inspect(controller))
                        print(device.address .. " has controller: " .. controller.address) -- DEBUG printing
                    end
                end
            end
        end
        print("--------------------") -- DEBUG printing
        print(#our_devices .. " = " .. (#our_devices - nr_sub_controllers) .. " devices + " .. nr_sub_controllers .. " sub-controllers") -- DEBUG printing
        print("just_starting = " .. tostring(just_starting))


        if #our_devices >= HIGH_WATERMARK then -- sub controller needed
            just_starting = false
            print("controller is preparing to offload...")
            print("--------------------") -- DEBUG printing

            -- elect sub-controller (or take an existing one)
            if nr_sub_controllers == 0 then
                sub_controller = our_devices[1]
                --table.remove(our_devices, 1) -- sub_controller are still part of our_devices
                --sub_controller = elect_sub_controller(devices) -- this java function needs a good score to be calculated
                print("selected sub_controller: " .. sub_controller.address) -- DEBUG printing
            elseif nr_sub_controllers > 0 then
                for id, device in pairs(devices) do
                    if device.is_sub_controller == true then
                        sub_controller = device
                    end
                end
                print("existing sub_controller: " .. sub_controller.address) -- DEBUG printing
            end

            -- elect devices to be offloaded (for now just take the first n devices)
            devices_to_handover = {}
            loop_limit = #our_devices - (LOW_WATERMARK + 1) -- we want to have LOW_WATERMARK + 1 devices later (sub_controller not treated special here --> could be offloaded as well --> potential problem)
            --print(loop_limit) -- DEBUG printing
            for i = 1, loop_limit do
                --devices_to_handover[our_devices[1].address] = our_devices[1] -- fill devices_to_handover in the (key-value) hash part of the LuaTable
                table.insert(devices_to_handover, our_devices[2]) -- fill devices_to_handover in the (iterable) array part of the LuaTable
                controller_of_devices[our_devices[2]] = sub_controller
                our_devices[2].controller_address = sub_controller
                table.remove(our_devices, 2)
            end
            -- devices_to_handover = elect_devices_to_handover(devices, #our_devices - (LOW_WATERMARK + 1))

            print("--------------------") -- DEBUG printing
            for id, device in pairs(devices_to_handover) do print("device to handover: " .. device.address) end -- DEBUG printing
            for i, device in ipairs(our_devices) do print("remaining our_device: " .. device.address) end -- DEBUG printing

            devices_to_handover = create_devices(devices_to_handover) -- make the LuaTable to a Devices object
            print("--------------------") -- DEBUG printing
            print("controller is offloading...") -- DEBUG printing
            print("--------------------") -- DEBUG printing

            sub_controller:make_sub_controller(devices_to_handover) -- make_sub_controller is also add_device (to sub_controller) if the device is already a sub_controller

        elseif (#our_devices <= LOW_WATERMARK) and (just_starting == false) then -- no sub-controller needed anymore, decommission it: (sub-)controller removes policies (stops sending them) --> devices go back to standard behaviour of trying to register at the top-level controller
            print("decommissioning a sub-controller")
            print("--------------------") -- DEBUG printing
            -- for the understanding: this script is run by a controller which can only see its sub-controllers and what devices they have to manage; it cannot see HOW this sub-controller manages its devices (sub-sub-controller)

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
            while #our_devices <= LOW_WATERMARK do
                -- find the sub_controller with the fewest devices to manage
                lowest_amount = 9223372036854775807 -- infinity
                for device, amount in pairs(sub_controllers_device_count) do
                    if amount <= lowest_amount then
                        sub_controller = device
                        lowest_amount = amount
                    end
                end
                print("decommissioning sub-controller " .. sub_controller.address)
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
            print("smile and wave") -- DEBUG printing
            print("--------------------") -- DEBUG printing
        end
    end
)

register_network(net)
