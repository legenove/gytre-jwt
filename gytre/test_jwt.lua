local JWT = require('lua.gytre.jwt')
local cjson = require('cjson')

local ngx = ngx
local error = error

local share_data = ngx.shared.share_data
local RSA_PUB_KEY = share_data:get('RSA_PUB_KEY')
local RSA_PRIV_KEY = share_data:get('RSA_PRIV_KEY')
local SECRET_KEY = share_data:get('JWT_SECRET_KEY')
local JWT_TTL = share_data:get('JWT_TTL')
local JWT_ALGORITHM = share_data:get('JWT_ALGORITHM')

local jwt = JWT:new({
    JWT_TTL = JWT_TTL,
    RSA_PUB_KEY = RSA_PUB_KEY,
    RSA_PRIV_KEY = RSA_PRIV_KEY,
    SECRET_KEY = SECRET_KEY
})
local preload = jwt.create_preload({
    iss = 'spring',
    aud = '123',
    name = 'legenove',
    img = 'hhaha'
})

local token = jwt:encode(preload,JWT_ALGORITHM)

print(token)

local data = jwt:decode(token)
print(cjson.encode(data))