-- Dzabede Nesta Protocol
-- declare our protocol
dn_proto = Proto("DNP","Dzabede Nesta Protocol")

-- create a function to dissect it



function msg_type(number)
    if number == "0" then
        return "RESERVED"
    elseif number == '1' then
        return "KEEP_ALIVE"
    elseif number == '2' then
        return "ESTABLISH_CONNECTION"
    elseif number == '3' then
        return "TERMINATE_CONNECTION"
    elseif number == '4' then
        return "SEND_MESSAGE"
    elseif number == '5' then
        return "SEND_FILE"
    elseif number == '6' then
        return "ERROR_IN_DELIVERY"
    elseif number == '7' then
        return "DELIVERY_OK"
    elseif number == '8' then
        return "SWITCH_ROLES"
    elseif number == '9' then
        return "FILE_BIGGER_THAN_2MB"
    else
        return "UNKNOWN"
    end
end


function dn_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "Dzabede Nesta Protocol"
    if buffer:len() == 1 then
        local subtree = tree:add(dn_proto, buffer(), "Dzabede Nesta Protocol Data")
        subtree:add(buffer(0),  "Msg Type:          " .. buffer(0):string() .. " (" .. msg_type(buffer(0,1):string()) .. ")" )
    else
        local subtree = tree:add(dn_proto, buffer(), "Dzabede Nesta Protocol Data")
        subtree:add(buffer(0,1),"Msg Type:          " .. buffer(0,1):string() .. " (" .. msg_type(buffer(0,1):string()) .. ")" )
        subtree:add(buffer(1,2),"Packet Length:     " .. buffer(1,2):uint())
        subtree:add(buffer(3,2),"Fragment count:    " .. buffer(3,2):uint())
        subtree:add(buffer(5,2),"Fragment number:   " .. buffer(5,2):uint())
        subtree:add(buffer(7,1),"Checksum:          " .. buffer(7,1):uint())
        subtree:add(buffer(8),  "Payload (Data):    " .. buffer(8):string())
        
    end
    --subtree:add(buffer(0,2),"The first two bytes: " .. buffer(0,2):uint())
    --subtree = subtree:add(buffer(2,2),"The next two bytes")
    --subtree:add(buffer(2,1),"The 3rd byte: " .. buffer(2,1):uint())
    --subtree:add(buffer(3,1),"The 4th byte: " .. buffer(3,1):uint())
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
udp_table:add(12345, dn_proto)
udp_table:add(18080, dn_proto)
udp_table:add(18081, dn_proto)