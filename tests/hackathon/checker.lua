-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

if (tx_type == "TRANSFER" or tx_type == "CASH_OUT") and tonumber(amt) > 200000 then 
	return true 
else 
	return false 
end
