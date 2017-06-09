local string_gsub = string.gsub
local string_format = string.format
local string_byte = string.byte
local string_char = string.char
local tonumber = tonumber

local _M = { _VERSION = '0.01' }

_M.decodeURI = function(s)
    s = string_gsub(s, '%%(%x%x)', function(h) return string_char(tonumber(h, 16)) end)
    return s
end

_M.encodeURI = function(s)
    s = string_gsub(s, "([^%w%.%- ])", function(c) return string_format("%%%02X", string_byte(c)) end)
    return string_gsub(s, " ", "+")
end

return _M
