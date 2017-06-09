local rsa = require("lua.gytre.rsa")

local key_name = 'spring'
if key_name == nil then
    error('need a key name')
end

local error = error


local rsa_public_key, rsa_priv_key, err = rsa:generate_rsa_keys(2048)
if not rsa_public_key then
    error('generate rsa keys err: ', err)
end
local path = "..."

local public_file = io.open(path .. key_name .. "_public_key.pem", "r")
if public_file then
    error('rsa keys already exits')
end

local public_file = io.open(path .. key_name .. "_public_key.pem", "w")
public_file:write(rsa_public_key)
public_file:close()


local private_file = io.open(path .. key_name .. "_private_key.pem", "w")
private_file:write(rsa_priv_key)
private_file:close()

