HIGH_WATERMARK = 10 -- device count for when to offload onto a new sub-controller
LOW_WATERMARK = 2 -- device count for when to decommission a sub-controller

-- in the naming scheme, "we" are the top-level controller of this network
-- if the controller of the device is the top-level controller ("us"), then the device.controllerAddress = ""

local our_devices = {} -- unordered list of all our devices
local controller_of_devices = {} -- mapping of device to its controller

net = create_network()
--net:add_node("n1", {ip="10.1.0.42/24"})

net:set_callback(
    function(my_net, devices) -- set_callback is called every 5000ms
        just_starting = true
        our_devices = {}
        print(inspect(devices))

        for id, device in pairs(devices) do
            -- DEBUG printing
            --print(inspect(device))
            --print("device.controllerAddress: " .. device.controller_address)
            --print("device.is_sub_controller: " .. tostring(device.is_sub_controller))

            if device.is_sub_controller == true then -- device is sub-controller
                controller_of_devices[device] = ""
            elseif device.controller_address ~= "" then -- device controlled by sub-controller
                controller_of_devices[device] = device.controller_address
            elseif device.controller_address == "" then -- device controlled by "us" (top-level controller)
                table.insert(our_devices, device)
                controller_of_devices[device] = ""
            end
        end

        -- DEBUG printing
        --print(inspect(our_devices)) --inspecting of a full table doesn't work that easily, would need extra function
        for i, device in ipairs(our_devices) do print(inspect(device)) end

        if next(our_devices) == nil then
            print("no devices registered yet")
        else
            print("--------------------")
            for device, controller in pairs(controller_of_devices) do
                if controller == "" then
                    print(inspect(device) .. " has standard controller")
                else
                    print(inspect(device) .. " has controller: " .. controller)
                end
            end
            print("--------------------")
        end

        if #our_devices >= HIGH_WATERMARK then -- sub controller needed
            just_starting = false
            print("controller is preparing to offload...")

            -- elect sub controller (for now take simply the first)
            sub_controller = our_devices[1]
            --sub_controller = elect_sub_controller(devices) -- this java function needs a good score to be calculated
            sub_controller.is_sub_controller = true

            -- elect devices to be offloaded (for now just take the first n devices)
            devices_to_handover = {}
            for i = 1, #our_devices - LOW_WATERMARK do
                devices_to_handover[i] = our_devices[1]
                controller_of_devices[our_devices[1]] = sub_controller -- this makes the devices_to_handover variable useless, but maybe its needed with a more sophisticated solution
                our_devices[1].controllerAddress = sub_controller
                table.remove(our_devices, 1)
            end
            -- devices_to_handover = elect_devices_to_handover(devices, #our_devices - LOW_WATERMARK)

            -- DEBUG printing
            for i, device in ipairs(our_devices) do print(inspect(device)) end
            print("-----")
            for i, device in ipairs(devices_to_handover) do print(inspect(device)) end
            print("-----")
            for device, controller in pairs(controller_of_devices) do print(inspect(device) .. " has controller: " .. controller) end
            print("-----")

            -- actually create the sub-controller
            print("controller is offloading...")
            dev:make_sub_controller(devices_to_handover)

        elseif just_starting == false and #our_devices <= LOW_WATERMARK then -- no sub controller needed anymore, get nodes back
            print("decommissioning a sub-controller")

            -- two options for decommissioning a sub_controller:
            --      sub_controller sends last will to its nodes
            --      CA revokes certificate for sub_controller & nodes timeout
            -- second version probably better as its easier to implement and a repeating check by the devices to their controller is a good idea

            for i, device in ipairs(devices) do
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
            print("well, what now?")
        end
    end
)

register_network(net)
