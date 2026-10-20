-- Owner: Adam — Lua script that flags plaintext credential submissions.
-- Called by sid 9000002 in plaintext_creds.rules. Returns 1 only when a password field
-- carries a non-empty value in an unencrypted HTTP request body (form or JSON).
-- The body is only inspected in memory; nothing from it is logged or written anywhere.
-- Suricata 8: the rule's http.request_body sticky buffer is passed in as args["buffer"].

function init(args)
    return {buffer = true}
end

function match(args)
    local raw = args["buffer"]
    if raw == nil or #raw == 0 then
        return 0
    end

    local body = "&" .. string.lower(raw)
    local fields = {"password", "passwd", "pass", "pwd"}

    for _, field in ipairs(fields) do
        local form_value = string.match(body, "&" .. field .. "=([^&]+)")
        local json_value = string.match(body, '"' .. field .. '"%s*:%s*"([^"]+)"')

        if form_value ~= nil or json_value ~= nil then
            return 1
        end
    end

    return 0
end