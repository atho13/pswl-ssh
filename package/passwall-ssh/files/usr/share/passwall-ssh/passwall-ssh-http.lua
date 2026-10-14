#!/usr/bin/env lua

local socket = require("socket")

-- ============================================================
-- 1. LOGGER
-- ============================================================
local LOG = "/tmp/etc/passwall-ssh.log"

local function log(msg)
    local f = io.open(LOG, "a")
    if f then
        f:write(string.format("[%s] %s\n", os.date("%Y-%m-%d %H:%M:%S"), tostring(msg)))
        f:close()
    end
end

local function log_status(msg)
    local f = io.open(LOG, "a")
    if f then
        f:write(string.format("<font color=\"#FFFF00\">[%s] %s</font>\n",
            os.date("%Y-%m-%d %H:%M:%S"), tostring(msg)))
        f:close()
    end
end

local function log_payload(title, payload)
    if not payload or payload == "" then return end
    log(title)
    for line in payload:gmatch("([^\r\n]+)") do
        log(line)
    end
end

-- ============================================================
-- 2. ENVIRONMENT / ROUTING
-- ============================================================
local ENV_FILE = "/usr/share/passwall-ssh/passwall-ssh.env"

local function load_env(path)
    local f = io.open(path, "r")
    if not f then return {} end

    local env = {}
    for line in f:lines() do
        if line ~= "" and not line:match("^%s*#") then
            local key, value = line:match("^([%w_]+)%s*=%s*['\"]?(.-)['\"]?%s*$")
            if key then env[key] = value end
        end
    end
    f:close()
    return env
end

local ENV = load_env(ENV_FILE)
local PAYLOAD_FILE = "/usr/share/passwall-ssh/passwall-ssh.payload"
local LISTEN_HOST = "127.0.0.1"
local LISTEN_PORT = tonumber(ENV.LISTEN_PORT) or 8080
local REMOTE_HOST, REMOTE_PORT

if ENV.TRANSPORT == "TLS" then
    REMOTE_HOST = "127.0.0.1"
    REMOTE_PORT = tonumber(ENV.STUNNEL_PORT) or 4444
    if ENV.PROXY and ENV.PROXY ~= "" then
        log("Mode: TLS/SNI via Stunnel + HTTP Proxy -> " .. tostring(ENV.PROXY))
    else
        log("Mode: TLS/SNI via Stunnel (Direct)")
    end
else
    if ENV.PROXY and ENV.PROXY ~= "" then
        REMOTE_HOST = ENV.PROXY
        REMOTE_PORT = tonumber(ENV.PROXY_PORT) or 80
        log("Mode: TCP via HTTP Proxy -> " .. tostring(REMOTE_HOST) .. ":" .. tostring(REMOTE_PORT))
    else
        REMOTE_HOST = ENV.HOST
        REMOTE_PORT = tonumber(ENV.HOST_PORT) or 80
        log("Mode: Direct TCP Injector -> " .. tostring(REMOTE_HOST) .. ":" .. tostring(REMOTE_PORT))
    end
end

if not REMOTE_HOST or REMOTE_HOST == "" then
    REMOTE_HOST = "127.0.0.1"
end

-- ============================================================
-- 3. RESOURCE / TIMEOUT SETTINGS
-- ============================================================
-- 32 KiB gives a reasonable compromise between syscall/event frequency and
-- per-iteration memory on small OpenWrt routers. Benchmark 16/32/64 KiB later.
local READ_SIZE = 65536
local MAX_HTTP_HEADER = 16 * 1024
local QUEUE_HIGH = 256 * 1024
local QUEUE_LOW = 64 * 1024
local CONNECT_TIMEOUT = 10
local INITIAL_HEADER_TIMEOUT = 15
local IDLE_TIMEOUT = 300
local SELECT_TIMEOUT = 1.0
local MAX_WRITE_PER_EVENT = 512 * 1024
local MAX_ACCEPTS_PER_EVENT = 16

local SELECT_LIMIT = tonumber(socket._SETSIZE) or 64
local SAFE_SESSION_LIMIT = math.max(1, math.floor((SELECT_LIMIT - 1) / 2))
local MAX_SESSIONS = math.max(1, math.min(
    tonumber(ENV.MAX_SESSIONS) or 30,
    SAFE_SESSION_LIMIT
))

log(string.format(
    "HTTP engine: read=%d high=%d low=%d max_sessions=%d select_limit=%d",
    READ_SIZE, QUEUE_HIGH, QUEUE_LOW, MAX_SESSIONS, SELECT_LIMIT
))

-- ============================================================
-- 4. PAYLOAD LOADING / TAG TRANSLATION
-- ============================================================
local f = io.open(PAYLOAD_FILE, "rb")
local RAW_PAYLOAD = ""
if f then
    RAW_PAYLOAD = f:read("*a") or ""
    f:close()
end

local USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
local t_sec = os.time()
local t_ms = math.floor((socket.gettime() % 1) * 1000)
math.randomseed(t_sec + t_ms)

local function generate_ws_key()
    local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local key = {}
    for i = 1, 22 do
        local rand = math.random(1, #chars)
        key[#key + 1] = chars:sub(rand, rand)
    end
    key[#key + 1] = "=="
    return table.concat(key)
end

local function safe_sub(str, pattern, repl)
    if not str then return "" end
    return (str:gsub(pattern, function() return tostring(repl or "") end))
end

local function expand_multipliers(payload)
    if not payload then return "" end
    return payload:gsub("%[([%w_%-]+)%*(%d+)%]", function(token, count)
        local n = tonumber(count) or 1
        return string.rep("[" .. token .. "]", n)
    end)
end

local ROTATE_FILE = "/tmp/etc/passwall-rotate.tmp"

local function get_persistent_rotate()
    local rf = io.open(ROTATE_FILE, "r")
    if rf then
        local val = tonumber(rf:read("*a"))
        rf:close()
        return val or 0
    end
    return 0
end

local function set_persistent_rotate(val)
    local wf = io.open(ROTATE_FILE, "w")
    if wf then
        wf:write(tostring(val))
        wf:close()
    end
end

local RAW_EXPANDED = expand_multipliers(RAW_PAYLOAD)
local STATIC_PAYLOAD = RAW_EXPANDED

STATIC_PAYLOAD = STATIC_PAYLOAD:gsub("\\\\", "\\")
STATIC_PAYLOAD = STATIC_PAYLOAD:gsub("\\r\\n", "\r\n")
STATIC_PAYLOAD = STATIC_PAYLOAD:gsub("\\r", "\r")
STATIC_PAYLOAD = STATIC_PAYLOAD:gsub("\\n", "\n")
STATIC_PAYLOAD = safe_sub(STATIC_PAYLOAD, "%[crlf%]", "\r\n")
STATIC_PAYLOAD = safe_sub(STATIC_PAYLOAD, "%[lf%]", "\n")
STATIC_PAYLOAD = safe_sub(STATIC_PAYLOAD, "%[cr%]", "\r")
STATIC_PAYLOAD = safe_sub(STATIC_PAYLOAD, "%[protocol%]", "HTTP/1.1")
STATIC_PAYLOAD = safe_sub(STATIC_PAYLOAD, "%[ua%]", USER_AGENT)
STATIC_PAYLOAD = safe_sub(STATIC_PAYLOAD, "%[proxy%]", ENV.PROXY or "")
STATIC_PAYLOAD = safe_sub(STATIC_PAYLOAD, "%[proxy_host%]", ENV.PROXY or "")
STATIC_PAYLOAD = safe_sub(STATIC_PAYLOAD, "%[proxy_port%]", ENV.PROXY_PORT or "")
STATIC_PAYLOAD = safe_sub(STATIC_PAYLOAD, "%[sni%]", ENV.SNI or "")
STATIC_PAYLOAD = safe_sub(STATIC_PAYLOAD, "%[sni_host%]", ENV.SNI or "")
STATIC_PAYLOAD = safe_sub(STATIC_PAYLOAD, "%[sni_port%]", "443")

local function parse_tags_dynamic(payload, host, port, client_raw_request, request_method)
    if not payload then return "" end

    local SSH_HOST = ENV.HOST or host or ""
    local SSH_PORT = tostring(ENV.HOST_PORT or port or 80)
    local SSH_HOST_PORT = SSH_HOST .. ":" .. SSH_PORT

    local method = request_method or "GET"
    if not request_method and client_raw_request and client_raw_request ~= "" then
        local m = client_raw_request:match("^([A-Z]+)%s+")
        if m and m ~= "SSH" then
            method = m
        elseif client_raw_request:find("^CONNECT") then
            method = "CONNECT"
        end
    end

    local res = payload
    res = safe_sub(res, "%[host%]", SSH_HOST)
    res = safe_sub(res, "%[server%]", SSH_HOST)
    res = safe_sub(res, "%[ssh%]", SSH_HOST)
    res = safe_sub(res, "%[ssh_host%]", SSH_HOST)
    res = safe_sub(res, "%[ip%]", SSH_HOST)
    res = safe_sub(res, "%[host_no_port%]", SSH_HOST)
    res = safe_sub(res, "%[port%]", SSH_PORT)
    res = safe_sub(res, "%[ssh_port%]", SSH_PORT)
    res = safe_sub(res, "%[host_port%]", SSH_HOST_PORT)
    res = safe_sub(res, "%[ip_port%]", SSH_HOST_PORT)
    res = res:gsub("%[ws_key%]", generate_ws_key)
    res = res:gsub("%[ws%-key%]", generate_ws_key)
    res = safe_sub(res, "%[method%]", method)
    res = safe_sub(res, "%[raw%]", client_raw_request or "")
    res = safe_sub(res, "%[real_raw%]", client_raw_request or "")
    res = safe_sub(res, "%[realData%]", client_raw_request or "")
    res = safe_sub(res, "%[netData%]", client_raw_request or "")

    res = res:gsub("%[rotate=([^%]]+)%]", function(list)
        local items = {}
        for item in list:gmatch("[^;]+") do items[#items + 1] = item end
        if #items > 0 then
            local current_index = get_persistent_rotate()
            current_index = (current_index % #items) + 1
            set_persistent_rotate(current_index)
            return items[current_index]
        end
        return ""
    end)

    res = res:gsub("%[random=([^%]]+)%]", function(list)
        local items = {}
        for item in list:gmatch("[^;]+") do items[#items + 1] = item end
        if #items > 0 then return items[math.random(1, #items)] end
        return ""
    end)

    return res
end

local function generate_steps(payload)
    local steps = {}
    local pos_ds = payload:find("[delay_split]", 1, true)
    local pos_s = payload:find("[split]", 1, true)

    if pos_ds then
        steps[#steps + 1] = { action = "SEND", data = payload:sub(1, pos_ds - 1) }
        steps[#steps + 1] = { action = "DELAY", ms = tonumber(ENV.DELAY) or 1000 }
        steps[#steps + 1] = { action = "SEND", data = payload:sub(pos_ds + 13) }
        steps[#steps + 1] = { action = "SEND_BANNER" }
    elseif pos_s then
        steps[#steps + 1] = { action = "SEND", data = payload:sub(1, pos_s - 1) }
        steps[#steps + 1] = { action = "WAIT_INCOMING_HTTP" }
        steps[#steps + 1] = { action = "SEND", data = payload:sub(pos_s + 7) }
        steps[#steps + 1] = { action = "SEND_BANNER" }
    else
        steps[#steps + 1] = { action = "SEND", data = payload }
        steps[#steps + 1] = { action = "SEND_BANNER" }
    end
    return steps
end

-- ============================================================
-- 5. SMALL FIFO QUEUE (HEAD/TAIL, BYTE ACCOUNTING)
-- ============================================================
local SendQueue = {}
SendQueue.__index = SendQueue

function SendQueue.new()
    return setmetatable({ head = 1, tail = 0, bytes = 0, chunks = {} }, SendQueue)
end

function SendQueue:push(data)
    if not data or #data == 0 then return end
    self.tail = self.tail + 1
    self.chunks[self.tail] = { data = data, offset = 1 }
    self.bytes = self.bytes + #data
end

function SendQueue:peek()
    if self.head > self.tail then return nil end
    return self.chunks[self.head]
end

function SendQueue:consume(count)
    if not count or count <= 0 or self.head > self.tail then return end

    local item = self.chunks[self.head]
    local remaining = #item.data - item.offset + 1
    if count > remaining then count = remaining end

    item.offset = item.offset + count
    self.bytes = self.bytes - count

    if item.offset > #item.data then
        self.chunks[self.head] = nil
        self.head = self.head + 1
    end

    if self.head > self.tail then
        self.head = 1
        self.tail = 0
        self.bytes = 0
    elseif self.head > 1024 and self.head > (self.tail / 2) then
        -- Rare compaction prevents indices growing indefinitely without shifting
        -- on every pop. This is amortized and only runs when the head is large.
        local new_chunks = {}
        local n = 0
        for i = self.head, self.tail do
            local v = self.chunks[i]
            if v then
                n = n + 1
                new_chunks[n] = v
            end
        end
        self.chunks = new_chunks
        self.head = 1
        self.tail = n
    end
end

-- ============================================================
-- 6. SOCKET SETS WITH O(1) REMOVE
-- ============================================================
local server, bind_err = socket.bind(LISTEN_HOST, LISTEN_PORT)
if not server then
    log("FATAL BIND ERROR: " .. tostring(bind_err))
    os.exit(1)
end
server:settimeout(0)

local read_sockets, read_index = { server }, { [server] = 1 }
local write_sockets, write_index = {}, {}
local session_by_socket = {}
local sessions = {}
local active_sessions = 0

local function add_socket(list, index, sock)
    if not sock or index[sock] then return end
    list[#list + 1] = sock
    index[sock] = #list
end

local function remove_socket(list, index, sock)
    local idx = index[sock]
    if not idx then return end

    local last_idx = #list
    local last_sock = list[last_idx]
    if idx ~= last_idx then
        list[idx] = last_sock
        index[last_sock] = idx
    end
    list[last_idx] = nil
    index[sock] = nil
end

local function add_read(sock)
    add_socket(read_sockets, read_index, sock)
end

local function remove_read(sock)
    remove_socket(read_sockets, read_index, sock)
end

local function set_wants_write(sock, wants)
    if wants then
        add_socket(write_sockets, write_index, sock)
    else
        remove_socket(write_sockets, write_index, sock)
    end
end

local function find_header_end(buf)
    local p = buf:find("\r\n\r\n", 1, true)
    if p then return p, 4 end
    p = buf:find("\n\n", 1, true)
    if p then return p, 2 end
    return nil, nil
end

local function find_line_end(buf)
    local p = buf:find("\r\n", 1, true)
    if p then return p, 2 end
    p = buf:find("\n", 1, true)
    if p then return p, 1 end
    return nil, nil
end

local function looks_like_http_request(buf)
    local first_line = buf:match("^([^\r\n]*)") or buf
    if first_line:match("^[A-Z]+%s+%S+%s+HTTP/%d+%.%d+") then return true end
    if first_line:match("^CONNECT%s+[^%s]*$") then return true end
    if first_line:match("^[A-Z]+$") and #first_line <= 16 then return true end
    if first_line:match("^[A-Z]+%s+[^%s]*$") and #first_line < 2048 then return true end
    return false
end

local function looks_like_http_response_prefix(buf)
    if #buf == 0 then return true end
    local prefix = "HTTP/"
    if #buf < #prefix and prefix:sub(1, #buf) == buf then return true end
    return buf:sub(1, #prefix) == prefix
end

-- Forward declarations; these functions call each other through the session state.
local cleanup
local refresh_interests
local queue_to_remote
local queue_to_client
local execute_sequence
local resume_waiting_sequence
local parse_response_buffer
local maybe_shutdown
local start_upstream

-- ============================================================
-- 7. SESSION / QUEUE HELPERS
-- ============================================================
local function new_session(client, now)
    local sess = {
        client = client,
        remote = nil,
        phase = "INIT",             -- INIT, CONNECTING, READY
        out_state = "INIT",         -- INIT, RUNNING, WAIT_DELAY, WAIT_INCOMING_HTTP, DONE
        out_steps = {},
        out_index = 1,
        delay_until = nil,
        connect_started = nil,
        created_at = now,
        last_active = now,
        initial_buffer = "",
        banner = "",
        in_need_200 = false,
        tunnel_established = false,
        http_buffer = "",
        skip_remaining = nil,
        chunked_state = nil,
        chunk_remaining = 0,
        pending_tunnel = false,
        last_logged_status = "",
        to_remote = SendQueue.new(),
        to_client = SendQueue.new(),
        client_read_closed = false,
        remote_read_closed = false,
        client_send_shutdown = false,
        remote_send_shutdown = false,
        client_read_paused = false,
        remote_read_paused = false,
        closed = false,
    }

    sessions[sess] = true
    active_sessions = active_sessions + 1
    session_by_socket[client] = sess
    add_read(client)
    return sess
end

cleanup = function(sess, reason)
    if not sess or sess.closed then return end
    sess.closed = true

    if reason then log("Session closed: " .. tostring(reason)) end

    local client, remote = sess.client, sess.remote
    if client then
        remove_read(client)
        set_wants_write(client, false)
        session_by_socket[client] = nil
        pcall(function() client:close() end)
    end
    if remote then
        remove_read(remote)
        set_wants_write(remote, false)
        session_by_socket[remote] = nil
        pcall(function() remote:close() end)
    end

    sessions[sess] = nil
    active_sessions = math.max(0, active_sessions - 1)
    sess.to_remote = nil
    sess.to_client = nil
    sess.initial_buffer = nil
    sess.http_buffer = nil
    sess.banner = nil
end

local function update_backpressure(sess)
    if not sess or sess.closed then return end

    -- Hysteresis: pause at the high watermark, resume only after draining
    -- to the low watermark. This avoids repeatedly adding/removing sockets
    -- when a queue fluctuates around one threshold.
    if not sess.client_read_paused and sess.to_remote.bytes >= QUEUE_HIGH then
        sess.client_read_paused = true
    elseif sess.client_read_paused and sess.to_remote.bytes <= QUEUE_LOW then
        sess.client_read_paused = false
    end

    if not sess.remote_read_paused and sess.to_client.bytes >= QUEUE_HIGH then
        sess.remote_read_paused = true
    elseif sess.remote_read_paused and sess.to_client.bytes <= QUEUE_LOW then
        sess.remote_read_paused = false
    end
end

refresh_interests = function(sess)
    if not sess or sess.closed then return end
    update_backpressure(sess)

    local client_can_read = false
    if sess.client and not sess.client_read_closed and not sess.client_read_paused and
        (sess.phase == "INIT" or (sess.phase == "READY" and sess.out_state == "DONE")) then
        client_can_read = true
    end

    if client_can_read then add_read(sess.client) else remove_read(sess.client) end

    local remote_can_read = false
    if sess.remote and sess.phase == "READY" and not sess.remote_read_closed and
        not sess.remote_read_paused then
        remote_can_read = true
    end

    if remote_can_read then add_read(sess.remote) else remove_read(sess.remote) end

    if sess.remote then
        local remote_needs_write = (sess.phase == "CONNECTING") or (sess.to_remote and sess.to_remote.bytes > 0)
        set_wants_write(sess.remote, remote_needs_write)
    end

    if sess.client then
        set_wants_write(sess.client, sess.to_client and sess.to_client.bytes > 0)
    end
end

queue_to_remote = function(sess, data)
    if not sess or sess.closed or not data or data == "" then return end
    sess.to_remote:push(data)
    refresh_interests(sess)
end

queue_to_client = function(sess, data)
    if not sess or sess.closed or not data or data == "" then return end
    sess.to_client:push(data)
    refresh_interests(sess)
end

maybe_shutdown = function(sess)
    if not sess or sess.closed then return end

    -- A client half-close should only be propagated after all payload/banner data
    -- has been scheduled and the client->remote queue is completely drained.
    if sess.phase == "READY" and sess.client_read_closed and
        sess.out_state == "DONE" and sess.to_remote.bytes == 0 and
        not sess.remote_send_shutdown and sess.remote then
        local ok, result, shutdown_err = pcall(function() return sess.remote:shutdown("send") end)
        if not ok or not result then
            log("Remote send shutdown: " .. tostring(shutdown_err or result))
        end
        sess.remote_send_shutdown = true
    end

    -- Tell the client that the upstream send stream ended, after queued bytes
    -- have reached the client socket. The client->remote direction may continue.
    if sess.remote_read_closed and sess.to_client.bytes == 0 and
        not sess.client_send_shutdown and sess.client then
        local ok, result, shutdown_err = pcall(function() return sess.client:shutdown("send") end)
        if not ok or not result then
            log("Client send shutdown: " .. tostring(shutdown_err or result))
        end
        sess.client_send_shutdown = true
    end

    if sess.client_read_closed and sess.remote_read_closed and
        sess.to_remote.bytes == 0 and sess.to_client.bytes == 0 then
        cleanup(sess, "both directions reached EOF")
        return
    end

    refresh_interests(sess)
end

-- ============================================================
-- 8. PAYLOAD SEQUENCE
-- ============================================================
execute_sequence = function(sess)
    if not sess or sess.closed or sess.phase ~= "READY" then return end

    sess.out_state = "RUNNING"
    while sess.out_index <= #sess.out_steps do
        local step = sess.out_steps[sess.out_index]

        if step.action == "SEND" then
            if step.data and #step.data > 0 then
                log_payload("Queued Payload Part", step.data)
                queue_to_remote(sess, step.data)
            end
            sess.out_index = sess.out_index + 1

        elseif step.action == "SEND_BANNER" then
            if sess.banner and #sess.banner > 0 then
                queue_to_remote(sess, sess.banner)
                sess.banner = ""
            end
            sess.out_index = sess.out_index + 1

        elseif step.action == "DELAY" then
            sess.out_state = "WAIT_DELAY"
            sess.delay_until = socket.gettime() + ((step.ms or 1000) / 1000)
            refresh_interests(sess)
            return

        elseif step.action == "WAIT_INCOMING_HTTP" then
            sess.out_state = "WAIT_INCOMING_HTTP"
            refresh_interests(sess)
            return

        else
            log("Unknown payload sequence action: " .. tostring(step.action))
            sess.out_index = sess.out_index + 1
        end
    end

    sess.out_state = "DONE"
    sess.delay_until = nil
    refresh_interests(sess)
    maybe_shutdown(sess)
end

resume_waiting_sequence = function(sess)
    if not sess or sess.closed or sess.out_state ~= "WAIT_INCOMING_HTTP" then return end
    sess.out_index = sess.out_index + 1
    sess.out_state = "RUNNING"
    execute_sequence(sess)
end

local function complete_connect(sess)
    if not sess or sess.closed or sess.phase ~= "CONNECTING" then return end

    sess.phase = "READY"
    sess.connect_started = nil
    sess.remote:settimeout(0)
    pcall(function() sess.remote:setoption("tcp-nodelay", true) end)
    add_read(sess.remote)

---log("Upstream connected: " .. tostring(REMOTE_HOST) .. ":" .. tostring(REMOTE_PORT))
    sess.out_state = "RUNNING"
    execute_sequence(sess)
    refresh_interests(sess)
end

-- ============================================================
-- 9. UPSTREAM CONNECT / INITIAL REQUEST
-- ============================================================
start_upstream = function(sess, target_host, target_port, payload_input, request_method)
    if not sess or sess.closed then return end

    local translated_payload = parse_tags_dynamic(
        STATIC_PAYLOAD,
        target_host,
        target_port,
        payload_input,
        request_method
    )

    sess.out_steps = generate_steps(translated_payload)
    sess.out_index = 1
    sess.out_state = "CONNECTING"
    sess.phase = "CONNECTING"
    sess.connect_started = socket.gettime()

    local remote, create_err = socket.tcp()
    if not remote then
        cleanup(sess, "cannot create upstream socket: " .. tostring(create_err))
        return
    end

    sess.remote = remote
    session_by_socket[remote] = sess
    remote:settimeout(0)
    pcall(function() remote:setoption("tcp-nodelay", true) end)

    -- With timeout 0, LuaSocket returns immediately for an in-progress connect.
    -- A writable event is not considered success until getpeername() succeeds.
    local ok, conn_err = remote:connect(REMOTE_HOST, REMOTE_PORT)
    if ok then
        complete_connect(sess)
    elseif conn_err == "timeout" or
        (conn_err and conn_err:lower():find("progress", 1, true)) or
        (conn_err and conn_err:lower():find("already connected", 1, true)) then
        refresh_interests(sess)
    else
        cleanup(sess, "upstream connect failed: " .. tostring(conn_err))
    end
end

local function process_initial_request(sess)
    if not sess or sess.closed or sess.phase ~= "INIT" then return end

    local buf = sess.initial_buffer or ""
    local p, delim_len = find_header_end(buf)
    local request_header, extra

    if p then
        if p - 1 > MAX_HTTP_HEADER then
            cleanup(sess, "initial HTTP header exceeds limit")
            return
        end
        request_header = buf:sub(1, p + delim_len - 1)
        extra = buf:sub(p + delim_len)
    else
        if #buf > MAX_HTTP_HEADER then
            cleanup(sess, "initial request exceeds header limit")
            return
        end
        if looks_like_http_request(buf) then return end
        -- Backward-compatible fallback for a non-HTTP/raw initial stream.
        request_header = buf
        extra = ""
    end

    local request_line = request_header:match("^([^\r\n]+)") or ""
    local method = request_line:match("^([A-Z]+)%s+")
    local connect_target = request_header:match("^CONNECT%s+([^%s]+)")
    local payload_host, payload_port = REMOTE_HOST, REMOTE_PORT
    local payload_input

    if connect_target then
        sess.in_need_200 = true
        local h, pnum = connect_target:match("^([^:]+):(%d+)$")
        if h then payload_host = h; payload_port = tonumber(pnum) end
        -- Preserve legacy [raw] behavior for CONNECT profiles: only bytes that
        -- arrived after the CONNECT header are passed to [raw], while [method]
        -- is now correctly set to CONNECT.
        sess.banner = extra
        payload_input = extra
        method = "CONNECT"
    else
        -- For ordinary HTTP requests, the initial bytes are sent only after the
        -- injector payload, in the same order as the original implementation.
        sess.banner = buf
        payload_input = buf
    end

    sess.initial_buffer = ""
    start_upstream(sess, payload_host, payload_port, payload_input, method)
end

-- ============================================================
-- 10. RESPONSE PARSER / STREAMED INTERMEDIATE BODY DISCARD
-- ============================================================
local function finish_non_tunnel_response(sess)
    if sess.out_state == "WAIT_INCOMING_HTTP" then
        resume_waiting_sequence(sess)
    end
end

local function establish_tunnel(sess)
    if not sess or sess.closed or sess.tunnel_established then return end

    if sess.in_need_200 then
        queue_to_client(sess, "HTTP/1.0 200 Connection established\r\n\r\n")
        sess.in_need_200 = false
    end

    sess.tunnel_established = true
    local remainder = sess.http_buffer or ""
    sess.http_buffer = ""
    if remainder ~= "" then queue_to_client(sess, remainder) end

    if sess.out_state == "WAIT_INCOMING_HTTP" then
        resume_waiting_sequence(sess)
    end
    refresh_interests(sess)
end

local function consume_chunked_body(sess)
    while not sess.closed do
        local state = sess.chunked_state
        local buf = sess.http_buffer or ""

        if state == "SIZE" then
            local p, len = find_line_end(buf)
            if not p then
                if #buf > MAX_HTTP_HEADER then
                    cleanup(sess, "oversized chunk-size line")
                end
                return false
            end

            local line = buf:sub(1, p - 1)
            local hex = line:match("^%s*([%x]+)")
            if not hex then
                cleanup(sess, "invalid chunked response size")
                return false
            end

            local size = tonumber(hex, 16)
            if not size then
                cleanup(sess, "invalid chunked response size")
                return false
            end

            sess.http_buffer = buf:sub(p + len)
            if size == 0 then
                sess.chunked_state = "TRAILERS"
            else
                sess.chunk_remaining = size
                sess.chunked_state = "DATA"
            end

        elseif state == "DATA" then
            local remaining = sess.chunk_remaining or 0
            if remaining <= 0 then
                sess.chunked_state = "DATA_END"
            elseif #buf == 0 then
                return false
            elseif #buf < remaining then
                sess.chunk_remaining = remaining - #buf
                sess.http_buffer = ""
                return false
            else
                sess.http_buffer = buf:sub(remaining + 1)
                sess.chunk_remaining = 0
                sess.chunked_state = "DATA_END"
            end

        elseif state == "DATA_END" then
            if buf:sub(1, 2) == "\r\n" then
                sess.http_buffer = buf:sub(3)
            elseif buf:sub(1, 1) == "\n" then
                sess.http_buffer = buf:sub(2)
            elseif #buf < 2 then
                return false
            else
                cleanup(sess, "invalid chunked response delimiter")
                return false
            end
            sess.chunked_state = "SIZE"

        elseif state == "TRAILERS" then
            if buf:sub(1, 2) == "\r\n" then
                sess.http_buffer = buf:sub(3)
                sess.chunked_state = nil
                return true
            elseif buf:sub(1, 1) == "\n" then
                sess.http_buffer = buf:sub(2)
                sess.chunked_state = nil
                return true
            else
                local p, len = find_header_end(buf)
                if p then
                    if p - 1 > MAX_HTTP_HEADER then
                        cleanup(sess, "oversized chunked response trailers")
                        return false
                    end
                    sess.http_buffer = buf:sub(p + len)
                    sess.chunked_state = nil
                    return true
                end
                if #buf > MAX_HTTP_HEADER then
                    cleanup(sess, "oversized chunked response trailers")
                end
                return false
            end
        else
            cleanup(sess, "invalid chunked parser state")
            return false
        end
    end
    return false
end

parse_response_buffer = function(sess)
    if not sess or sess.closed then return end

    while not sess.closed and not sess.tunnel_established do
        local buf = sess.http_buffer or ""

        -- Stream-discard response bodies with a Content-Length instead of storing
        -- the complete body in RAM. A successful 200/101 with Content-Length is
        -- treated like the old parser: consume that body before tunnel mode.
        if sess.skip_remaining and sess.skip_remaining > 0 then
            if #buf == 0 then return end
            local consumed = math.min(sess.skip_remaining, #buf)
            sess.http_buffer = buf:sub(consumed + 1)
            sess.skip_remaining = sess.skip_remaining - consumed
            if sess.skip_remaining > 0 then return end
            sess.skip_remaining = nil

            if sess.pending_tunnel then
                sess.pending_tunnel = false
                establish_tunnel(sess)
                return
            end
            finish_non_tunnel_response(sess)
            -- Continue in case another response is already in the buffer.

        elseif sess.chunked_state then
            local complete = consume_chunked_body(sess)
            if sess.closed then return end
            if not complete then return end
            finish_non_tunnel_response(sess)
            -- Any bytes after the chunked body may be the next response.

        else
            local p, delim_len = find_header_end(buf)
            if not p then
                if #buf > MAX_HTTP_HEADER then
                    cleanup(sess, "upstream HTTP header exceeds limit")
                    return
                end

                if #buf >= 5 and not looks_like_http_response_prefix(buf) then
                    -- Same fallback as the legacy parser: non-HTTP upstream bytes
                    -- indicate that the stream should be forwarded transparently.
                    establish_tunnel(sess)
                    return
                end
                return
            end

            if p - 1 > MAX_HTTP_HEADER then
                cleanup(sess, "upstream HTTP header exceeds limit")
                return
            end

            local header = buf:sub(1, p - 1)
            local status_line = header:match("^([^\r\n]+)")
            local status_code = tonumber(header:match("^HTTP/%d+%.%d+%s+(%d%d%d)"))
            if status_line and status_line:match("^HTTP/1%.") then
                if sess.last_logged_status ~= status_line then
                    log_status(status_line)
                    sess.last_logged_status = status_line
                end
            end

            if not status_code then
                cleanup(sess, "malformed upstream HTTP status line")
                return
            end

            sess.http_buffer = buf:sub(p + delim_len)
            local lower_header = header:lower()
            local cl = lower_header:match("content%-length:%s*(%d+)")
            local body_len = tonumber(cl) or 0
            local is_chunked = lower_header:match("transfer%-encoding:[^\n]*chunked") ~= nil
            local is_tunnel_status = (status_code == 200 or status_code == 101)

            if body_len > 0 then
                sess.skip_remaining = body_len
                sess.pending_tunnel = is_tunnel_status
                -- Loop immediately to consume as much of the body as is already
                -- present, without keeping the full response body in memory.

            elseif is_tunnel_status then
                -- For CONNECT/injector success without Content-Length, bytes after
                -- the header are tunnel bytes (including any chunk-looking bytes).
                establish_tunnel(sess)
                return

            elseif is_chunked then
                sess.chunked_state = "SIZE"
                sess.chunk_remaining = 0

            else
                -- Keep legacy behavior for unframed intermediate responses: the
                -- header ends the response for split-payload sequencing purposes.
                finish_non_tunnel_response(sess)
            end
        end
    end
end

local function process_remote_data(sess, chunk)
    if not sess or sess.closed or not chunk or #chunk == 0 then return end

    if sess.tunnel_established then
        queue_to_client(sess, chunk)
        return
    end

    sess.http_buffer = (sess.http_buffer or "") .. chunk
    parse_response_buffer(sess)
end

-- ============================================================
-- 11. SOCKET READ / WRITE HANDLERS
-- ============================================================
local function handle_client_data(sess, chunk)
    if not sess or sess.closed or not chunk or #chunk == 0 then return end

    if sess.phase == "INIT" then
        sess.initial_buffer = (sess.initial_buffer or "") .. chunk
        process_initial_request(sess)
    else
        -- During payload delays / split waits, read interest is disabled. Any data
        -- already returned by select is ignored if the socket was paused meanwhile.
        queue_to_remote(sess, chunk)
    end
end

local function mark_client_eof(sess)
    if not sess or sess.closed or sess.client_read_closed then return end
    sess.client_read_closed = true
    remove_read(sess.client)

    if sess.phase == "INIT" then
        cleanup(sess, "client closed before a complete request")
        return
    end
    maybe_shutdown(sess)
end

local function mark_remote_eof(sess)
    if not sess or sess.closed or sess.remote_read_closed then return end

    -- If the upstream sent a short non-HTTP banner (for example, only a few
    -- bytes) and then closed, flush it as raw stream data instead of stranding
    -- it forever in the response peek buffer. An incomplete HTTP header/body is
    -- a failed handshake, so close rather than leave the client hanging.
    if not sess.tunnel_established then
        local pending = sess.http_buffer or ""
        if #pending > 0 and not looks_like_http_response_prefix(pending) and
            not sess.skip_remaining and not sess.chunked_state then
            establish_tunnel(sess)
        else
            cleanup(sess, "upstream closed before tunnel establishment")
            return
        end
    end

    sess.remote_read_closed = true
    if sess.remote then remove_read(sess.remote) end
    maybe_shutdown(sess)
end

local function handle_readable(sock)
    if sock == server then
        -- Drain a bounded number of accepts without blocking, so a burst of new
        -- connections cannot starve established sessions in the event loop.
        local accepted_count = 0
        while accepted_count < MAX_ACCEPTS_PER_EVENT do
            local client, accept_err = server:accept()
            if not client then
                if accept_err and accept_err ~= "timeout" then
                    log("Accept failed: " .. tostring(accept_err))
                end
                break
            end

            accepted_count = accepted_count + 1
            if active_sessions >= MAX_SESSIONS then
                pcall(function() client:close() end)
                log("Connection rejected: maximum active sessions reached")
            else
                client:settimeout(0)
                pcall(function() client:setoption("tcp-nodelay", true) end)
                new_session(client, socket.gettime())
            end
        end
        return
    end

    local sess = session_by_socket[sock]
    if not sess or sess.closed then return end
    -- The select result is a snapshot. Ignore a socket paused/removed while
    -- another ready socket was processed earlier in this same iteration.
    if not read_index[sock] then return end

    local data, recv_err, partial = sock:receive(READ_SIZE)
    local chunk = data or partial or ""
    if #chunk > 0 then
        sess.last_active = socket.gettime()
        if sock == sess.client then
            handle_client_data(sess, chunk)
        elseif sock == sess.remote then
            process_remote_data(sess, chunk)
        end
    end

    if sess.closed then return end

    if recv_err == "closed" then
        if sock == sess.client then
            mark_client_eof(sess)
        elseif sock == sess.remote then
            mark_remote_eof(sess)
        end
    elseif recv_err and recv_err ~= "timeout" then
        cleanup(sess, "receive failed: " .. tostring(recv_err))
    end
end

local function write_from_queue(sock, sess, queue)
    if not queue or queue.bytes <= 0 then return true end

    local budget = MAX_WRITE_PER_EVENT
    while not sess.closed and queue.bytes > 0 and budget > 0 do
        local item = queue:peek()
        if not item then break end

        local offset = item.offset
        local sent, send_err, last = sock:send(item.data, offset)
        local bytes_sent = 0

        if sent then
            -- LuaSocket returns the last byte index in the original string.
            bytes_sent = sent - offset + 1
        elseif send_err == "timeout" then
            -- On a timeout, `last` is also the last byte index sent. With no
            -- progress, it is normally offset-1 or nil.
            if last then bytes_sent = last - offset + 1 end
            if bytes_sent <= 0 then break end
        else
            cleanup(sess, "send failed: " .. tostring(send_err))
            return false
        end

        if bytes_sent > 0 then
            if bytes_sent > ( #item.data - offset + 1 ) then
                bytes_sent = #item.data - offset + 1
            end
            queue:consume(bytes_sent)
            budget = budget - bytes_sent
            sess.last_active = socket.gettime()
        else
            break
        end

        if send_err == "timeout" then break end
    end

    return not sess.closed
end

local function handle_writable(sock)
    local sess = session_by_socket[sock]
    if not sess or sess.closed or not write_index[sock] then return end

    if sock == sess.remote and sess.phase == "CONNECTING" then
        -- Writable means connect completed, either successfully or with an error.
        -- getpeername() differentiates success from a failed TCP handshake.
        local peer = sock:getpeername()
        if not peer then
            cleanup(sess, "nonblocking upstream connect failed")
            return
        end
        complete_connect(sess)
        if sess.closed then return end
    end

    if sock == sess.remote then
        if sess.to_remote and sess.to_remote.bytes > 0 then
            if not write_from_queue(sock, sess, sess.to_remote) then return end
        end
    elseif sock == sess.client then
        if sess.to_client and sess.to_client.bytes > 0 then
            if not write_from_queue(sock, sess, sess.to_client) then return end
        end
    end

    if sess.closed then return end
    refresh_interests(sess)
    maybe_shutdown(sess)
end

-- ============================================================
-- 12. MAIN EVENT LOOP
-- ============================================================
while true do
    local now = socket.gettime()
    local wait_timeout = SELECT_TIMEOUT

    for sess in pairs(sessions) do
        if not sess.closed then
            if now - sess.last_active > IDLE_TIMEOUT then
                cleanup(sess, "idle timeout")
            elseif sess.phase == "INIT" and now - sess.created_at > INITIAL_HEADER_TIMEOUT then
                cleanup(sess, "initial request timeout")
            elseif sess.phase == "CONNECTING" and sess.connect_started and
                now - sess.connect_started > CONNECT_TIMEOUT then
                cleanup(sess, "upstream connect timeout")
            elseif sess.out_state == "WAIT_DELAY" and sess.delay_until then
                local remaining = sess.delay_until - now
                if remaining <= 0 then
                    sess.delay_until = nil
                    sess.out_index = sess.out_index + 1
                    sess.out_state = "RUNNING"
                    execute_sequence(sess)
                elseif remaining < wait_timeout then
                    wait_timeout = remaining
                end
            end
        end
    end

    local ok, readable, writable, select_err = pcall(
        socket.select, read_sockets, write_sockets, wait_timeout
    )

    if not ok then
        log("socket.select exception: " .. tostring(readable))
        socket.sleep(0.05)
    else
        if select_err and select_err ~= "timeout" then
            log("socket.select failed: " .. tostring(select_err))
            socket.sleep(0.05)
        else
            if readable then
                for _, sock in ipairs(readable) do
                    handle_readable(sock)
                end
            end
            if writable then
                for _, sock in ipairs(writable) do
                    handle_writable(sock)
                end
            end
        end
    end
end
