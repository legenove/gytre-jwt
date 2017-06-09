local string_gsub = string.gsub
local string_format = string.format
local string_byte = string.byte
local string_char = string.char
local string_find = string.find
local table_insert = table.insert
local table_sort = table.sort
local pairs = pairs
local tonumber = tonumber
local type = type

local _M = { _VERSION = '0.01' }

_M.decodeURI = function(s)
    s = string_gsub(s, '%%(%x%x)', function(h) return string_char(tonumber(h, 16)) end)
    return s
end

_M.encodeURI = function(s)
    s = string_gsub(s, "([^%w%.%- ])", function(c) return string_format("%%%02X", string_byte(c)) end)
    return string_gsub(s, " ", "+")
end


_M.startswith = function(str, substr)
    if str == nil or substr == nil then
        return nil, "the string or the sub-stirng parameter is nil"
    end
    if string_find(str, substr) ~= 1 then
        return false
    else
        return true
    end
end

_M.table_dict_sort = function(dict)
    local keys = {}
    local res = {}
    for i in pairs(dict) do table_insert(keys, i) end
    table_sort(keys)
    for i,v in pairs(keys) do res[v]=dict[v] end
    return res
end

_M.table_copy_table = function(self, ori_tab)
    if (type(ori_tab) ~= "table") then
        return nil
    end
    local new_tab = {}
    for i,v in pairs(ori_tab) do
        local vtyp = type(v)
        if (vtyp == "table") then
            new_tab[i] = self.table_copy_table(v)
        elseif (vtyp == "thread") then
            new_tab[i] = v
        elseif (vtyp == "userdata") then
            new_tab[i] = v
        else
            new_tab[i] = v
        end
    end
    return new_tab
end

_M.table_merge = function( tDest, tSrc )
    for k, v in pairs( tSrc ) do
        tDest[k] = v
    end
end

return _M
