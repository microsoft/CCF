-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

if (tx_type == 2 or tx_type == 3) and tonumber(amt) > 200000 then 
	return true 
else 
	return false 
end
