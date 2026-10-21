-- Owner: Adam — Lua script that flags plaintext credential submissions.
-- Called by sid 9000002 in plaintext_creds.rules. Returns 1 only when a password field
-- carries non-empty value in unencrypted HTTP request body (form or JSON).
-- Suricata 8: reads the body through the suricata.http library (sticky buffers are not
-- passed to lua: keywords).

local http = require("suricata.http")

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil then
        return 0
    end

    local chunks = tx:request_body()
    if chunks == nil then
        return 0
    end

    local fields = {"password", "passwd", "pass", "pwd"}

    for _, chunk in ipairs(chunks) do
        local body = "&" .. string.lower(chunk)

        for _, field in ipairs(fields) do
            local form_value = string.match(body, "&" .. field .. "=([^&]+)")
            local json_value = string.match(body, '"' .. field .. '"%s*:%s*"([^"]+)"')

            if form_value ~= nil or json_value ~= nil then
                return 1
            end
        end
    end

    return 0
end