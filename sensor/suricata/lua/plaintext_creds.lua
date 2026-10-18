-- Owner: Adam — Lua script that flags plaintext credential submissions.
-- Called by sid 9000002 in plaintext_creds.rules. Returns 1 only when a password field
-- carries a non-empty value in an unencrypted HTTP request body (form or JSON).
-- The body is only inspected in memory; nothing from it is logged or written anywhere.

function init(args)
    local needs = {}
    needs["http.request_body"] = tostring(true)
    return needs
end

function match(args)
    local chunks = HttpGetRequestBody()
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
