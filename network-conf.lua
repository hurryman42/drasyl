HIGH_WATERMARK = 3 -- device count for when to offload onto a new sub-controller
LOW_WATERMARK = 1 -- device count for when to decommission a sub-controller

-- in the naming scheme, "we" are the top-level controller of this network
-- if the controller of the device is the top-level controller ("us"), then the device.controllerAddress = ""

local our_devices = {} -- unordered list of all our devices
local controller_of_devices = {} -- mapping of device to its controller

net = create_network()
net:add_node("n1", {ip="10.1.0.42/8"})

net:set_callback(
    function(my_net, devices) -- set_callback is called every 5000ms
        just_starting = true
        our_devices = {}
        nr_sub_controllers = 0
        print(inspect(devices)) -- DEBUG printing

        for id, device in pairs(devices) do
            --print(inspect(device)) -- DEBUG printing
            --print("device.controllerAddress: " .. device.controller_address) -- DEBUG printing
            --print("device.is_sub_controller: " .. tostring(device.is_sub_controller)) -- DEBUG printing

            if device.is_sub_controller == true then -- device is sub-controller
                controller_of_devices[device] = ""
                nr_sub_controllers = nr_sub_controllers + 1
            elseif device.controller_address ~= "" then -- device controlled by sub-controller
                controller_of_devices[device] = device.controller_address
            elseif device.controller_address == "" then -- device controlled by "us" (top-level controller)
                table.insert(our_devices, device)
                controller_of_devices[device] = ""
            end
        end

        --for i, device in ipairs(our_devices) do print(inspect(device)) end -- DEBUG printing

        if next(our_devices) == nil then
            print("no devices registered yet")
        else
            print("--------------------")
            for device, controller in pairs(controller_of_devices) do
                if controller == "" then
                    print(inspect(device) .. " has standard controller")
                else
                    print(inspect(device) .. " has controller: " .. inspect(controller))
                end
            end
            print("--------------------")
        end

        -- if the luatable is not an indexed one but rather a map, the # won't work and you would have to count the number of elements manually like this:
        --nr_our_devices = 0
        --for _ in pairs(our_devices) do
        --    nr_our_devices = nr_our_devices + 1
        --end

        nr_managed_devs = #our_devices + nr_sub_controllers
        print(nr_managed_devs) -- DEBUG printing

        if nr_managed_devs >= HIGH_WATERMARK then -- sub controller needed
            just_starting = false
            print("controller is preparing to offload...")

            -- elect sub controller (for now take simply the first)
            sub_controller = our_devices[1]
            sub_controller_index = 1
            --sub_controller = elect_sub_controller(devices) -- this java function needs a good score to be calculated
            sub_controller.is_sub_controller = true
            table.remove(our_devices, sub_controller_index)
            print("selected sub_controller: " .. inspect(sub_controller)) -- DEBUG printing

            -- elect devices to be offloaded (for now just take the first n devices)
            devices_to_handover = {}
            loop_limit = nr_managed_devs - LOW_WATERMARK - 1 -- the -1 keeps the new sub_controller out of the calculation
            --print(loop_limit)
            for i = 1, loop_limit do
                table.insert(devices_to_handover, our_devices[1]) -- fill devices_to_handover in the (iterable) array part of the LuaTable
                --devices_to_handover[our_devices[1].address] = our_devices[1] -- fill devices_to_handover in the (key-value) hash part of the LuaTable
                controller_of_devices[our_devices[1]] = sub_controller
                our_devices[1].controller_address = sub_controller
                table.remove(our_devices, 1)
            end
            -- devices_to_handover = elect_devices_to_handover(devices, nr_managed_devs - LOW_WATERMARK - 1)

            print("--------------------") -- DEBUG printing
            for id, device in pairs(devices_to_handover) do print("device to handover: " .. inspect(device)) end -- DEBUG printing
            for i, device in ipairs(our_devices) do print("remaining our_device: " .. inspect(device)) end -- DEBUG printing
            --for device, controller in pairs(controller_of_devices) do print(inspect(device) .. " has controller: " .. inspect(controller)) end -- DEBUG printing
            devices_to_handover = create_devices(devices_to_handover) -- make the LuaTable to a Devices object
            print(inspect(devices_to_handover)) -- DEBUG printing
            print("--------------------") -- DEBUG printing

            print("controller is offloading...") -- DEBUG printing
            sub_controller:make_sub_controller(devices_to_handover)

        elseif nr_managed_devs <= LOW_WATERMARK and just_starting == false then -- no sub controller needed anymore, get nodes back
            print("decommissioning a sub-controller")

            -- two options for decommissioning a sub_controller:
            --      sub_controller sends last will to its nodes
            --      CA revokes certificate for sub_controller & nodes timeout
            -- second version probably better as its easier to implement and a repeating check by the devices to their controller is a good idea

            for id, device in pairs(devices) do
                while #our_devices <= LOW_WATERMARK do
                    if device.is_sub_controller == true then
                        sub_controller = device
                        for device, controller in pairs(controller_of_devices) do
                            if controller == sub_controller then
                                controller_of_devices[device] = top_level_controller
                                add_device(net)
                                table.insert(our_devices, device)
                            end
                        end
                        --subnet = get_network(device)
                        --devices = get_devices(subnet)
                        --links = get_links(subnet)
                        --for id, device in pairs(devices) do
                        --    add_device(net)
                        --    table.insert(our_devices, device)
                        --end
                        --for i, link in ipairs(links) do add_link(net) end
                    end
                end
            end
            just_starting = true
        else
            print("smile and wave")
        end
    end
)

register_network(net)
