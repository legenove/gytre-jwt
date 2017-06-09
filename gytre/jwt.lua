local crypto = require("crypto")
local cjson = require("cjson")
local hmac = require("crypto.hmac")
local rsa = require "lua.gytre.rsa"
local util = require "lua.gytre.util"
local ngx = ngx
local os_time = os.time
local ngx_b64_encode = ngx.encode_base64
local ngx_b64_decode = ngx.decode_base64
local table_insert = table.insert
local table_sort = table.sort
local table_concat = table.concat
local error = error
local pairs = pairs
local setmetatable = setmetatable
local type = type

local _M = {
    _VERSION = '0.01' ,
    JWT_TTL = 60,
    RSA_PUB_KEY = nil,
    RSA_PRIV_KEY = nil,
    SECRET_KEY = nil,
}

local function table_dict_sort(dict)
    local keys = {}
    local res = {}
    for i in pairs(dict) do table_insert(keys, i) end
    table_sort(keys)
    for i,v in pairs(keys) do res[v]=dict[v] end
    return res
end

local function rsa_encode(algorithm, data, pub_key)
    local pub, err = rsa:new({
        public_key = pub_key,
        padding = rsa.PADDING.RSA_PKCS1_PADDING,
        algorithm = algorithm, --  "SHA256"
    })

    if not pub then
        error("new public rsa err:" .. err)
        ngx.exit(500)
        return
    end
    local encrypted, err = pub:encrypt(data)
    if not encrypted then
        error("failed to encrypt: " .. err)
        return
    end
    return ngx_b64_encode(encrypted)
end

local function rsa_decode(algorithm, signature, priv_key)
    local priv, err = rsa:new({
        private_key = priv_key,
        padding = rsa.PADDING.RSA_PKCS1_PADDING,
        algorithm = algorithm,
    })

    if not priv then
        error("new priv rsa err:" .. err)
        ngx.exit(500)
        return
    end

    local decrypted = priv:decrypt(ngx_b64_decode(signature))
    return decrypted
end

local function hmac_encode(algorithm, data, key)
    return ngx.encode_base64(hmac.digest(algorithm, data, key, true))
end

local function tokenize(str, div, len)
	local result, pos = {}, 0

	for st, sp in function() return str:find(div, pos, true) end do

		result[#result + 1] = str:sub(pos, st-1)
		pos = sp + 1

		len = len - 1

		if len <= 1 then
			break
		end
	end

	result[#result + 1] = str:sub(pos)

	return result
end

local alg_sign = {
	['HS256'] = function(data, key) return hmac_encode('sha256', data, key) end,
	['HS384'] = function(data, key) return hmac_encode('sha384', data, key) end,
	['HS512'] = function(data, key) return hmac_encode('sha512', data, key) end,
    ['RS256'] = function(data, pub_key) return rsa_encode('SHA256', data, pub_key) end,
}

local alg_verify = {
	['HS256'] = function(data, signature, key) return signature == alg_sign['HS256'](data, key) end,
	['HS384'] = function(data, signature, key) return signature == alg_sign['HS384'](data, key) end,
	['HS512'] = function(data, signature, key) return signature == alg_sign['HS512'](data, key) end,
    ['RS256'] = function(data, signature, priv_key) return data == rsa_decode('SHA256', signature, priv_key) end,
}

local preload = {
    --    iss (Issuer) Token签发者
    --sub (Subject) 主题
    --aud (Audience) 接收者
    --exp (Expiration Time) 过期时间-UNIX时间戳，必须大于签发时间
    --nbf (Not Before) 指定一个UNIX时间戳之前，此TOKEN是不可用的
    --iat (Issued At) 签发时间-UNIX时间戳
    --jti (JWT ID) Token唯一身份标识
    iss='',
    aud='',
    exp=0,
    nbf=0,
    iat=0,
    jti=""
}

--lua table 拷贝
local function table_copy_table(ori_tab)
    if (type(ori_tab) ~= "table") then
        return nil
    end
    local new_tab = {}
    for i,v in pairs(ori_tab) do
        local vtyp = type(v)
        if (vtyp == "table") then
            new_tab[i] = table_copy_table(v)
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

local function table_merge( tDest, tSrc )
    for k, v in pairs( tSrc ) do
        tDest[k] = v
    end
end

local function gen_jwt_id()
    return ngx_b64_encode(3193174198+os_time())
end

function _M:new(o)
    o = o or {}
    self.__index = self
    setmetatable(o, self)
    return o
end

function _M.create_preload(o)
    o = o or {}
    o.exp = o.exp or (os_time() + _M.JWT_TTL)
    o.nbf = o.nbf or (os_time())
    o.iat = o.nbf or (os_time())
    o.jti = o.jti or (gen_jwt_id())
    local _preload = table_copy_table(preload)
    table_merge(_preload,o)
    return _preload
end

local startswith = function(str, substr)
    if str == nil or substr == nil then
        return nil, "the string or the sub-stirng parameter is nil"
    end
    if string.find(str, substr) ~= 1 then
        return false
    else
        return true
    end
end


function _M:encode(data, alg)
	if type(data) ~= 'table' then return nil, "Argument #1 must be table" end
    data = table_dict_sort(data)
    local key
	alg = alg or "HS256"
    if startswith(alg,'HS') then
        key = self.SECRET_KEY
    else
        key = self.RSA_PUB_KEY
    end
    if type(key) ~= 'string' then return nil, "Argument key must be string" end

	if not alg_sign[alg] then
		return nil, "Algorithm not supported"
	end

	local header = { typ='JWT', alg=alg }

	local segments = {
		ngx_b64_encode(cjson.encode(header)),
		ngx_b64_encode(cjson.encode(data))
	}

	local signing_input = table_concat(segments, ".")

	segments[#segments+1] = alg_sign[alg](signing_input, key)

	return util.encodeURI(table_concat(segments, "."))
end

function _M:decode(data, verify)
	if verify == nil then verify = true end
	if type(data) ~= 'string' then return nil, "Argument #1 must be string" end
    local key
    data = util.decodeURI(data)
	local token = tokenize(data, '.', 3)

	if #token ~= 3 then
		return nil, "Invalid token"
	end

	local headerb64, bodyb64, sigb64 = token[1], token[2], token[3]

	local ok, header, body, sig = pcall(function ()

		return	cjson.decode(ngx_b64_decode(headerb64)),
			cjson.decode(ngx_b64_decode(bodyb64)),
			sigb64
	end)

	if not ok then
		return nil, "Invalid json"
	end

	if verify then

		if not header.typ or header.typ ~= "JWT" then
			return nil, "Invalid typ"
		end

		if not header.alg or type(header.alg) ~= "string" then
			return nil, "Invalid alg"
        end

		if body.exp and type(body.exp) ~= "number" then
			return nil, "exp must be number"
		end

		if body.nbf and type(body.nbf) ~= "number" then
			return nil, "nbf must be number"
        end
        if startswith(header.alg, 'HS') then
            key = self.SECRET_KEY
        else
            key = self.RSA_PRIV_KEY
        end

		if not alg_verify[header.alg] then
			return nil, "Algorithm not supported"
		end

		if not alg_verify[header.alg](headerb64 .. "." .. bodyb64, sig, key) then
			return nil, "Invalid signature"
		end

		if body.exp and os_time() >= body.exp then
			return nil, "Not acceptable by exp"
		end

		if body.nbf and os_time() < body.nbf then
			return nil, "Not acceptable by nbf"
		end
	end

	return body
end

return _M

