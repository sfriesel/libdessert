-- ----------------------------------------------------------------------------
-- Copyright 2009, David Gutzmann, Freie Universitaet Berlin (FUB).
-- Copyright 2010, Bastian Blywis, Freie Universitaet Berlin (FUB).
-- All rights reserved.

--These sources were originally developed by David Gutzmann,
--rewritten and extended by Bastian Blywis
--at Freie Universitaet Berlin (http://www.fu-berlin.de/),
--Computer Systems and Telematics / Distributed, embedded Systems (DES) group 
--(http://cst.mi.fu-berlin.de, http://www.des-testbed.net)
-- ----------------------------------------------------------------------------
--This program is free software: you can redistribute it and/or modify it under
--the terms of the GNU General Public License as published by the Free Software
--Foundation, either version 3 of the License, or (at your option) any later
--version.

--This program is distributed in the hope that it will be useful, but WITHOUT
--ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
--FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

--You should have received a copy of the GNU General Public License along with
--this program. If not, see http://www.gnu.org/licenses/ .
-- ----------------------------------------------------------------------------
--For further information and questions please use the web site
--       http://www.des-testbed.net
-- ----------------------------------------------------------------------------
 
-- Create a new dissector
DESTRACEREQ = Proto("dessert_ext_trace_req", "DESSERT-EXT-TRACE-REQ")

-- Create the protocol fields
local f = DESTRACEREQ.fields
f.extdata = ProtoField.ether("dessert.trace-req.extdata", "Extension data")

-- The dissector function
function DESTRACEREQ.dissector (buffer, pinfo, tree)
    pinfo.cols.protocol = "DESSERT-EXT-TRACE-REQ"
    
    local subtree = tree:add(DESTRACEREQ, buffer,"Extension Data")
    local offset = 0
    
    local extdata = buffer(offset, buffer:len())
    subtree:add(f.extdata,extdata)
    offset = offset + 6
    
    return offset
end



-- Create a new dissector
DESTRACERPL = Proto("dessert_ext_trace_rpl", "DESSERT-EXT-TRACE-RPL")

-- Create the protocol fields
local r = DESTRACERPL.fields
r.extdata = ProtoField.ether("dessert.trace-rpl.extdata", "Extension data")

-- The dissector function
function DESTRACERPL.dissector (buffer, pinfo, tree)
    pinfo.cols.protocol = "DESSERT-EXT-TRACE-REQ"
    
    local subtree = tree:add(DESTRACERPL, buffer,"Extension Data")
    local offset = 0
    local size = buffer:len()
    
    while offset < size do
      local extdata = buffer(offset, buffer:len())
      subtree:add(r.extdata,extdata)
      offset = offset + 6
    end
    
    return offset
end

_G.dessert_register_ext_dissector(0x02,"DESSERT_EXT_TRACE_REQ", DESTRACEREQ)
_G.dessert_register_ext_dissector(0x03,"DESSERT_EXT_TRACE_RPL", DESTRACERPL)
