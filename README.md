# gytre-jwt
JWT by ngx-lua

require crypto, cjson
mast be use in ngx-lua

### ngx.config -.-
```cpp
# init lua save the key and orther config
lua_shared_dict share_data 10m;
init_by_lua_file lua/init.lua;
server {

  ...
  
  location /jwt{
      default_type "text/html";
      content_by_lua_file ./lua/gytre/test_jwt.lua;
  }
}
```

### init.lua -.-
```lua
-- load rsa key --
local function read_files(fileName)
    local f = assert(io_open(fileName,'r'))
    local content = f:read("*all")
    f:close()
    return content
end
local path = '...'

local share_data = ngx.shared.share_data
share_data:set('RSA_PUB_KEY', read_files(path .. "./lua/gytre/spring_public_key.pem"))
share_data:set('RSA_PRIV_KEY', read_files(path .. "./lua/gytre/spring_private_key.pem"))

ngx.log(ngx.ERR, "=======finish rsa key initial=======")

share_data:set('JWT_SECRET_KEY', 'secret_key')
share_data:set('JWT_TTL', '60')
share_data:set('JWT_REFRESH_TTL', '30240')
share_data:set('JWT_ALGORITHM', 'HS512') --HS256, HS384, HS512, RS256

```

### test_jwt.lua -.-
see the [code](https://github.com/legenove/gytre-jwt/blob/master/gytre/test_jwt.lua)
