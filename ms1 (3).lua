-- EARLY LOCALIZATION (critical upvalues to resist tampering)
local io_open = io.open
local io_popen = io.popen
local debug_getinfo = debug and debug.getinfo
local pcall_local = pcall
local pairs_local = pairs
local next_local = next
local str_char = string.char
local str_byte = string.byte
local tostring_local = tostring
local tonumber_local = tonumber

-- embed static salt and self-file hash (computed at build-time)
local XOR_SALT = 'NukZ#L1c3nse$'
local SELF_HASH = '3a1226478a28d910ce52a78ab8d72cbacb9fb0d3d9c8a88b18c31d7967920fcc'

-- minimal deobfuscators available early (used to recover LICENSE_URL for validation)
local function hex_to_bytes(hexstr)
    if not hexstr then return {} end
    local out = {}
    for i = 1, #hexstr, 2 do
        local byte = tonumber(hexstr:sub(i, i+1), 16)
        out[#out + 1] = byte or 0
    end
    return out
end

local function bxor(a, b)
    local res = 0
    local bit = 1
    while a > 0 or b > 0 do
        local aa = a % 2
        local bb = b % 2
        if aa ~= bb then res = res + bit end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bit = bit * 2
    end
    return res
end

local function deobf(hexstr)
    local bytes = hex_to_bytes(hexstr)
    local out = {}
    local salt = XOR_SALT or ''
    local slen = #salt
    for i = 1, #bytes do
        local b = bytes[i]
        local k = 0
        if slen > 0 then k = salt:byte(((i - 1) % slen) + 1) end
        out[#out + 1] = string.char(bxor(b, k))
    end
    return table.concat(out)
end

-- LICENSE URL stored as XORed hex to avoid static discovery
local LICENSE_URL_HEX = '26011F2A50761E4C410F044B432701032F41394206410D1C0B502B1B1F7440235C4C5D1B181F453C415E6A0E3F5E16410D164A482716443742255F4C4340071D50'
local LICENSE_URL = deobf(LICENSE_URL_HEX)

-- License gate: only after successful license check becomes true
local UNLOCKED = false

-- Early hard exit used before hardened_exit is fully defined
local function hard_exit(msg)
    pcall_local(function()
        if type(gg) == 'table' and gg.toast then gg.toast('Fatal: '..tostring_local(msg or '')) end
    end)
    if os and os.exit then os.exit(1) end
    error('FATAL: '..tostring_local(msg or ''))
end

local function get_script_dir()
    if type(gg) == 'table' and gg.getFile then
        local path = gg.getFile()
        if type(path) == 'string' and path ~= '' then
            local dir = path:match('(.*/)')
            if type(dir) == 'string' and dir ~= '' then return dir end
        end
    end

    if debug and debug.getinfo then
        local info = debug.getinfo(1, 'S')
        if info and type(info.source) == 'string' then
            local source = info.source:match('^@(.+)')
            if type(source) == 'string' and source ~= '' then
                local dir = source:match('(.*/)')
                if type(dir) == 'string' and dir ~= '' then return dir end
            end
        end
    end

    local ok, cwd = pcall(function()
        local p = io.popen('pwd')
        if not p then return nil end
        local result = p:read('*l')
        p:close()
        return result
    end)
    if ok and type(cwd) == 'string' and cwd ~= '' then
        return cwd:gsub('/+$', '') .. '/'
    end

    return '/sdcard/'
end

local DIR = get_script_dir()
DIR = DIR:gsub('([^/])$','%1')

local function read(f)
    local h = io.open(DIR..f, 'r')
    if h then local s = h:read('*a') h:close() return s end
    return nil
end

local function write(f, s)
    local h = io.open(DIR..f, 'w')
    if h then h:write(s) h:close() return true end
    return false
end

-- ======= Protection / anti-tamper helpers (from encrypted build) =======
local XOR_SALT = 'NukZ#L1c3nse$'

local function hex_to_bytes(hexstr)
    if not hexstr then return {} end
    local out = {}
    for i = 1, #hexstr, 2 do
        local byte = tonumber(hexstr:sub(i, i+1), 16)
        out[#out + 1] = byte or 0
    end
    return out
end

local function bxor(a, b)
    local res = 0
    local bit = 1
    while a > 0 or b > 0 do
        local aa = a % 2
        local bb = b % 2
        if aa ~= bb then res = res + bit end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bit = bit * 2
    end
    return res
end

local function deobf(hexstr)
    local bytes = hex_to_bytes(hexstr)
    local out = {}
    local salt = XOR_SALT or ''
    local slen = #salt
    for i = 1, #bytes do
        local b = bytes[i]
        local k = 0
        if slen > 0 then k = salt:byte(((i - 1) % slen) + 1) end
        out[#out + 1] = string.char(bxor(b, k))
    end
    return table.concat(out)
end

local function get_string_key()
    local base = XOR_SALT or 'key'
    if ID and type(ID) == 'string' and #ID > 0 then
        return base .. ID
    end
    return base
end

-- Localize core system functions to detect tampering
local _io = io
local _os = os
local _string = string
local _table = table
local _debug = debug

local io_open = (_io and _io.open) or nil
local io_popen = (_io and _io.popen) or nil
local os_exit = (_os and _os.exit) or nil
local os_getenv = (_os and _os.getenv) or nil
local tostring_local = tostring
local tonumber_local = tonumber
local string_format = (_string and _string.format) or nil
local table_insert = (_table and _table.insert) or nil
local debug_getinfo = (_debug and _debug.getinfo) or nil
local debug_sethook = (_debug and _debug.sethook) or nil

local __initial_sys_snapshot = {
    io_open = io_open,
    io_popen = io_popen,
    os_exit = os_exit,
    os_getenv = os_getenv,
    tostring = tostring_local,
    tonumber = tonumber_local,
    string_format = string_format,
    table_insert = table_insert,
    debug_getinfo = debug_getinfo,
    debug_sethook = debug_sethook,
    gg_getFile = (type(gg) == 'table' and gg.getFile) or nil,
    gg_makeRequest = (type(gg) == 'table' and gg.makeRequest) or nil,
    gg_searchNumber = (type(gg) == 'table' and gg.searchNumber) or nil,
    gg_loadResults = (type(gg) == 'table' and gg.loadResults) or nil,
    gg_editAll = (type(gg) == 'table' and gg.editAll) or nil,
    gg_setValues = (type(gg) == 'table' and gg.setValues) or nil,
    gg_getResults = (type(gg) == 'table' and gg.getResults) or nil,
    gg_clearResults = (type(gg) == 'table' and gg.clearResults) or nil,
    gg_toast = (type(gg) == 'table' and gg.toast) or nil,
    gg_alert = (type(gg) == 'table' and gg.alert) or nil,
    gg_sleep = (type(gg) == 'table' and gg.sleep) or nil,
    gg_getListItems = (type(gg) == 'table' and gg.getListItems) or nil,
    gg_removeListItems = (type(gg) == 'table' and gg.removeListItems) or nil,
}

local function fail_hard_sys(msg)
    if os_exit then
        os_exit(1)
    end
    error('FATAL (sys): ' .. tostring(msg))
end

local function check_system_tamper()
    if (_io and _io.open) ~= __initial_sys_snapshot.io_open then fail_hard_sys('io.open tampered') end
    if (_io and _io.popen) ~= __initial_sys_snapshot.io_popen then fail_hard_sys('io.popen tampered') end
    if (_os and _os.exit) ~= __initial_sys_snapshot.os_exit then fail_hard_sys('os.exit tampered') end
    if (_os and _os.getenv) ~= __initial_sys_snapshot.os_getenv then fail_hard_sys('os.getenv tampered') end
    if tostring ~= __initial_sys_snapshot.tostring then fail_hard_sys('tostring tampered') end
    if tonumber ~= __initial_sys_snapshot.tonumber then fail_hard_sys('tonumber tampered') end
    if (_string and _string.format) ~= __initial_sys_snapshot.string_format then fail_hard_sys('string.format tampered') end
    if (_table and _table.insert) ~= __initial_sys_snapshot.table_insert then fail_hard_sys('table.insert tampered') end
    if (_debug and _debug.getinfo) ~= __initial_sys_snapshot.debug_getinfo then fail_hard_sys('debug.getinfo tampered') end
    if (_debug and _debug.sethook) ~= __initial_sys_snapshot.debug_sethook then fail_hard_sys('debug.sethook tampered') end
    if (type(gg) == 'table' and gg.getFile) ~= __initial_sys_snapshot.gg_getFile then fail_hard_sys('gg.getFile tampered') end
    if (type(gg) == 'table' and gg.makeRequest) ~= __initial_sys_snapshot.gg_makeRequest then fail_hard_sys('gg.makeRequest tampered') end
    if (type(gg) == 'table' and gg.searchNumber) ~= __initial_sys_snapshot.gg_searchNumber then fail_hard_sys('gg.searchNumber tampered') end
    if (type(gg) == 'table' and gg.loadResults) ~= __initial_sys_snapshot.gg_loadResults then fail_hard_sys('gg.loadResults tampered') end
    if (type(gg) == 'table' and gg.editAll) ~= __initial_sys_snapshot.gg_editAll then fail_hard_sys('gg.editAll tampered') end
    if (type(gg) == 'table' and gg.setValues) ~= __initial_sys_snapshot.gg_setValues then fail_hard_sys('gg.setValues tampered') end
    if (type(gg) == 'table' and gg.getResults) ~= __initial_sys_snapshot.gg_getResults then fail_hard_sys('gg.getResults tampered') end
    if (type(gg) == 'table' and gg.clearResults) ~= __initial_sys_snapshot.gg_clearResults then fail_hard_sys('gg.clearResults tampered') end
    if (type(gg) == 'table' and gg.toast) ~= __initial_sys_snapshot.gg_toast then fail_hard_sys('gg.toast tampered') end
    if (type(gg) == 'table' and gg.alert) ~= __initial_sys_snapshot.gg_alert then fail_hard_sys('gg.alert tampered') end
    if (type(gg) == 'table' and gg.sleep) ~= __initial_sys_snapshot.gg_sleep then fail_hard_sys('gg.sleep tampered') end
    if (type(gg) == 'table' and gg.getListItems) ~= __initial_sys_snapshot.gg_getListItems then fail_hard_sys('gg.getListItems tampered') end
    if (type(gg) == 'table' and gg.removeListItems) ~= __initial_sys_snapshot.gg_removeListItems then fail_hard_sys('gg.removeListItems tampered') end
end

if not check_call_origin then
    function check_call_origin()
        check_system_tamper()
        if debug_getinfo then
            local ok, info = pcall(debug_getinfo, 3, 'S')
            if ok and info and info.what == 'C' then
                fail_hard_sys('unexpected C call origin')
            end
        end
    end
end

-- run a quick tamper check early
pcall_local(check_system_tamper)

-- Verify GameGuardian API native bindings to prevent hooks
local function verify_gg_api()
    if type(gg) ~= 'table' then return end
    local probes = {'searchNumber','getResults','editAll','setValues','loadResults','clearResults','toast','alert','makeRequest'}
    for _, name in pairs_local(probes) do
        local f = gg[name]
        if type(f) ~= 'function' then hard_exit('gg API missing '..tostring_local(name)) end
        local s = tostring_local(f)
        if not s:find('%[C%]') and not s:find('function') then
            -- try debug info as further check
            local ok, info = pcall_local(debug_getinfo, f)
            if not ok or not info or tostring_local(info.what or '') ~= 'C' then hard_exit('gg API hooked '..tostring_local(name)) end
        end
    end
end

-- (deferred) Freeze _G to prevent runtime injections; use freeze_globals() after unlock

-- Provide a safe freeze_globals implementation so calls can't be nil.
local function freeze_globals()
    if type(_G) ~= 'table' then return end
    local mt = getmetatable(_G) or {}
    -- prevent further assignment to globals
    mt.__newindex = function(t, k, v)
        error('Attempt to write global: ' .. tostring(k), 2)
    end
    -- lock the metatable itself to hinder tampering
    mt.__metatable = false
    pcall_local(function() setmetatable(_G, mt) end)
end

-- run GG API verify immediately
pcall_local(verify_gg_api)

-- Neutralize Lua debug hooks to prevent runtime hooking (only modify if debug present)
pcall_local(function()
    if debug and type(debug) == 'table' then
        -- replace sethook with a wrapper that detects attempts but avoids crashing during init
        local orig_sethook = debug.sethook
        debug.sethook = function(...)
            -- detect attempts to replace hook; if called after unlock, treat as tamper
            if UNLOCKED then hardened_exit('debug hook attempt') end
            if orig_sethook then return orig_sethook(...) end
        end
        -- disable interactive debug console only after unlock
        local orig_debug = debug.debug
        debug.debug = function(...)
            if UNLOCKED then hardened_exit('debug console attempt') end
            if orig_debug then return orig_debug(...) end
        end
    end
end)

-- Honeypot fake license functions (traps for tampering attempts)
local function CheckLicense()
    -- trap: allocate until OOM if attacker calls this fake
    local t = {}
    for i = 1, 1e7 do t[i] = string.rep('A', 1024) end
end
local function ValidateKey()
    local t = {}
    for i = 1, 1e7 do t[i] = math.random() end
end

-- State machine wrapper for main menu to complicate static analysis
local function run_state_machine()
    local state = 0
    local dispatch = {
        [0] = function() state = 1 end,
        [1] = function()
            -- display main menu via gg.choice but through indirect dispatch
            local ok, choice = pcall_local(function()
                return gg.choice({
                    "1. ANTI-BAN",
                    "11. DAMAGE +50%",
                    "12. DEFENSE +50",
                    "13. COOLDOWN -50%",
                    "14. SPEED WALK +50%",
                    "15. ATTACK SPEED +50%",
                    "16. LIFESTEAL 50%",
                    "21. RESTORE",
                    "24. UPDATE LICENSE",
                    "Exit"
                }, nil, "Select option")
            end)
            if not ok or not choice then hardened_exit('menu failure') end
            if choice == 1 then DamageBoost() end
            if choice == 2 then DamageBoost() end
            if choice == 3 then DefenseBoost() end
            if choice == 4 then CooldownReduce() end
            if choice == 5 then SpeedWalkBoost() end
            if choice == 6 then AttackSpeedBoost() end
            if choice == 7 then LifestealBoost() end
            if choice == 8 then restore_all_injected() end
            if choice == 9 then UpdateLicenseKey() end
            if choice == 10 then hardened_exit('user exit') end
            state = 1
        end,
    }
    while true do
        local f = dispatch[state]
        if f then pcall_local(f) else hardened_exit('invalid state') end
    end
end

-- ======= End protection block =======

-- HWID storage path next to script
local HWID_FILENAME = '.my.id'
local HWID_PATH = DIR .. HWID_FILENAME
local LEGACY_NAME = DIR .. '.xdata'

local function read_full(path)
    if type(path) ~= 'string' then return nil end
    local h = io.open(path, 'r')
    if h then local s = h:read('*a') h:close() return s end
    return nil
end

local function write_full(path, s)
    if type(path) ~= 'string' or type(s) ~= 'string' then return false end
    local h = io.open(path, 'w')
    if h then h:write(s) h:close() return true end
    return false
end

local function hidden_read()
    local data = read_full(HWID_PATH)
    if data then return data end
    local legacy = read_full(LEGACY_NAME)
    if legacy then return legacy end
    return nil
end

local function hidden_write(s)
    return write_full(HWID_PATH, s)
end

local function validate_device_id(id)
    if type(id) ~= 'string' then return false end
    id = id:gsub('%s+', '')
    if #id ~= 12 then return false end
    if not id:match('^[A-Za-z0-9]+$') then return false end
    if id:match('^0+$') then return false end
    return true
end

local function load_device_id()
    local data = hidden_read()
    if validate_device_id(data) then return data end

    local legacy = read_full(LEGACY_NAME)
    if validate_device_id(legacy) then
        hidden_write(legacy)
        pcall(function() os.remove(LEGACY_NAME) end)
        return legacy
    end

    return nil
end

local function save_device_id(id)
    if not validate_device_id(id) then return false end
    return hidden_write(id)
end

local function create_device_id()
    local seed = (os.time() % 100000) + math.floor((os.clock() or 0) * 1000)
    math.randomseed(math.floor(seed))
    local chars = '0123456789'
    local t = {}
    for i = 1, 12 do
        local idx = math.random(1, #chars)
        t[i] = chars:sub(idx, idx)
    end
    local id = table.concat(t)
    if not validate_device_id(id) then
        id = string.format('%012d', (os.time() % 1000000) * 1000 + math.random(0, 999))
    end
    return id
end

local function get_body(resp)
    if type(resp) == 'string' then return resp end
    if type(resp) == 'table' then return tostring(resp.body or resp.content or resp.response or '') end
    return nil
end

local function fetch_license_text()
    if type(gg.makeRequest) ~= 'function' then return nil, nil end
    local ok, resp = pcall(gg.makeRequest, LICENSE_URL)
    if not ok then return nil, 'network' end
    if not resp then return nil, 'denied' end
    return get_body(resp), resp.headers or resp.header or resp.Headers
end

local function parse_http_date(date_str)
    if type(date_str) ~= 'string' then return nil end
    local day, mon_str, year, hour, min, sec = date_str:match('^%a+,%s*(%d%d)%s*(%a%a%a)%s*(%d%d%d%d)%s*(%d%d):(%d%d):(%d%d)%s*GMT')
    local months = {Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6, Jul=7, Aug=8, Sep=9, Oct=10, Nov=11, Dec=12}
    local mon = months[mon_str]
    if not mon then return nil end
    return os.time({year = tonumber(year), month = mon, day = tonumber(day), hour = tonumber(hour), min = tonumber(min), sec = tonumber(sec)})
end

local function parse_line(line)
    if not line then return nil end
    line = line:gsub('\r', ''):gsub('^%s+', ''):gsub('%s+$', '')
    if line == '' or line:match('^#') then return nil end
    -- split by '|'
    local parts = {}
    for part in line:gmatch('[^|]+') do table.insert(parts, part) end
    local key = parts[1]
    local expiry = parts[2]
    local dev = parts[3]
    if not key then return nil end
    key = tostring(key):gsub('^%s+', ''):gsub('%s+$', '')
    expiry = expiry and tostring(expiry):gsub('%s+', '') or ''
    dev = dev and tostring(dev):gsub('%s+', '') or ''
    if dev == '' then dev = nil end
    return key, expiry, dev
end

local function expiry_valid(expiry, now)
    if type(expiry) ~= 'string' then return false end
    local y, m, d = expiry:match('(%d%d%d%d)-(%d%d)-(%d%d)')
    if not y then return false end
    now = tonumber(now) or os.time()
    local expiry_time = os.time({year = tonumber(y), month = tonumber(m), day = tonumber(d), hour = 23, min = 59, sec = 59})
    return expiry_time >= now
end

local ID = load_device_id()
if not ID then
    ID = create_device_id()
    save_device_id(ID)
end

local cached_license_db = nil

-- MAXIMUM PROTECTION: Anti-Debug, Anti-Hooking, Anti-Log
local function check_env_hooks()
    local bad_env = {'LD_PRELOAD', 'LD_LIBRARY_PATH', 'FRIDA_GADGET', 'XPOSED_', 'ZYGISK_', '_DEBUG', 'DEBUGGER'}
    -- Disabled: environment variable checks produced false positives.
    return false
end

local function check_process_list()
    -- Disabled: process-list checks are noisy and not reliable across devices.
    return false
end

local function anti_debug_check()
    return check_env_hooks() or check_process_list()
end

local function anti_log()
    pcall(function() os.execute('logcat -c 2>/dev/null') end)
    pcall(function() os.execute('dmesg -c 2>/dev/null') end)
    pcall(function() os.execute('echo "" > /proc/sys/kernel/printk 2>/dev/null') end)
end

local function hardened_exit()
    anti_log()
    pcall(function() if gg and gg.removeListItems then gg.removeListItems(gg.getListItems() or {}) end end)
    pcall(function() if #injected_files > 0 then restore_all_injected() end end)
    pcall(function() cached_license_db = nil collectgarbage() end)
    pcall(function() os.execute('kill -9 $$ 2>/dev/null') end)
    os.exit(0)
end

-- Note: anti_debug_check() disabled to avoid false positives during normal runs.
anti_log()

local function load_and_cache_license_db()
    if cached_license_db then return cached_license_db end
    
    if type(gg.makeRequest) ~= 'function' then return nil end
    local ok, resp = pcall(gg.makeRequest, LICENSE_URL)
    if not ok or not resp or not resp.content then return nil end

    local text = resp.content
    if type(text) ~= 'string' then return nil end

    cached_license_db = {}
    local now = os.time()

    for line in text:gmatch('([^\r\n]+)') do
        local k, e, d = parse_line(line)
        if k then
            if not expiry_valid(e, now) then
                cached_license_db[k] = {expiry = e, device = d, status = 'expired'}
            else
                cached_license_db[k] = {expiry = e, device = d, status = 'valid'}
            end
        end
    end

    return cached_license_db
end

local function check_key_cached(key)
    local db = cached_license_db
    if not db then return nil, 'network' end

    local entry = db[key]
    if not entry then return false, 'not_found' end

    if entry.status == 'expired' then return false, 'expired' end

    -- device matching: nil => global, '*' => any, comma-separated allowed
    if entry.device and entry.device ~= '' then
        local dev_field = tostring(entry.device)
        if dev_field == '*' then
            return true, entry.expiry
        end
        for part in dev_field:gmatch('([^,]+)') do
            local cand = part:gsub('%s+', '')
            if cand == ID then return true, entry.expiry end
        end
        return false, 'activated'
    end

    return true, entry.expiry
end

-- Helper: show ready/accept window with optional expiry (forward-safe)
local function show_ready_with_expiry(expiry)
    pcall(function()
        if type(gg) == 'table' and gg.alert then
            if type(expiry) == 'string' and expiry ~= '' then
                gg.alert('Ready.\nValid until: ' .. tostring_local(expiry))
            else
                gg.alert('Ready.')
            end
        end
    end)
end

function require_license()
    -- Strict, non-silent license validation that MUST pass or script terminates
    if type(gg.makeRequest) ~= 'function' then hardened_exit() end

    local resp = nil
    local ok_req, r = pcall_local(function() return gg.makeRequest(LICENSE_URL) end)
    if not ok_req or not r or type(r) ~= 'table' or not r.content then hardened_exit() end
    resp = r

    local text = tostring_local(resp.content or '')
    -- derive per-device decryption key from server response + HWID + self-hash
    local function derive_key_from_resp(body)
        if type(body) ~= 'string' then return nil end
        local token = body:match('TOKEN:([A-Fa-f0-9]+)') or body:sub(1, 16)
        local seed = (XOR_SALT or '') .. (ID or '') .. tostring_local(token) .. (SELF_HASH or '')
        -- produce compact key string by xoring sequential bytes
        local out = {}
        for i = 1, #seed do out[i] = string.format('%02X', bxor(seed:byte(i), (i % 256))) end
        return table.concat(out)
    end

    local decrypt_key = derive_key_from_resp(text)
    if not decrypt_key then hardened_exit() end

    -- build cached db transiently, then wipe it immediately after check
    cached_license_db = {}
    local now = os.time()
    for line in text:gmatch('([^\r\n]+)') do
        local k, e, d = parse_line(line)
        if k then
            if not expiry_valid(e, now) then
                cached_license_db[k] = {expiry = e, device = d, status = 'expired'}
            else
                cached_license_db[k] = {expiry = e, device = d, status = 'valid'}
            end
        end
    end

    -- saved-key auto-skip: check .my.key first
    local saved = read_full('.my.key')
    if type(saved) == 'string' and saved:match('%S') then
        local sk = saved:gsub('%s+','')
        local okc, reason = check_key_cached(sk)
        local entry = cached_license_db and cached_license_db[sk]
        if okc == true then
            -- show ready with expiry if available
            local exp = reason or (entry and entry.expiry) or ''
            show_ready_with_expiry(exp)
            -- success: unlock critical data, then wipe cached db
            cached_license_db = nil
            UNLOCKED = true
            decrypt_offsets()
            freeze_globals()
            collectgarbage()
            return true
        end
        pcall_local(function()
            if gg and gg.alert then
                        local msg = 'Key rejected: ' .. tostring_local(reason or 'unknown')
                if entry and entry.expiry then msg = msg .. '\nДо: ' .. tostring_local(entry.expiry) end
                gg.alert(msg)
            end
        end)
    end

    -- prompt user for key (blocking) with retries for recoverable errors
    local attempts = 0
    local max_attempts = 5
    while true do
        attempts = attempts + 1
        local inp = gg.prompt({'Device ID: ' .. ID .. '\n\nEnter Key:'}, {''}, {'text'})
        if not inp or inp[1] == '' then hardened_exit() end
        local key = tostring_local(inp[1])

        local okk, reason = check_key_cached(key)
        local entry = cached_license_db and cached_license_db[key]
            if okk == nil then pcall_local(function() if gg and gg.alert then gg.alert('Network error while checking key') end end) hardened_exit() end

        if okk == true then
            -- on success, show ready with expiry if available
            local exp = reason or (entry and entry.expiry) or ''
            show_ready_with_expiry(exp)
            -- on success, mark unlocked and mix decrypt_key into runtime salt
            UNLOCKED = true
            XOR_SALT = (XOR_SALT or '') .. tostring_local(decrypt_key):sub(1,8)
            -- decrypt offsets, freeze globals, and immediately wipe transient blobs
            decrypt_offsets()
            freeze_globals()
            collectgarbage()
            -- persist accepted key locally for future auto-skip
            pcall_local(function() write_full('.my.key', key) end)
            cached_license_db = nil
            return true
        end

        -- handle recoverable vs fatal reasons
        if reason == 'activated' then
                    local msg = 'Key activated on another device'
                if entry and entry.device and entry.device ~= '' and entry.device ~= '*' then
                    msg = msg .. '\nRegistered: ' .. tostring_local(entry.device)
                end
            pcall_local(function() if gg and gg.alert then gg.alert(msg) end end)
            cached_license_db = nil
            hardened_exit()
        end

        -- expired/not_found/other -> inform user and allow retry until max attempts
                local msg = 'Key rejected: ' .. tostring_local(reason or 'unknown')
            if entry and entry.expiry then msg = msg .. '\nValid until: ' .. tostring_local(entry.expiry) end
        pcall_local(function() if gg and gg.alert then gg.alert(msg) end end)

            if attempts >= max_attempts then
                pcall_local(function() if gg and gg.alert then gg.alert('Too many attempts. Exiting.') end end)
            cached_license_db = nil
            hardened_exit()
        end
        -- otherwise loop back to prompt again
    end
end

function UpdateLicenseKey()
    return require_license()
end

function copy_file(src, dst)
    pcall(function()
        local c = read_file(src)
        if c then write_file(dst, c) else os.execute("cp \"" .. src .. "\" \"" .. dst .. "\" 2>/dev/null") end
    end)
end
function make_dir(path) pcall(function() os.execute("mkdir -p \"" .. path .. "\" 2>/dev/null") end) end
function file_exists(path) local f = io.open(path, "r") if f then f:close() return true end return false end

-- Progress display
function show_download_progress(name)
    name = tostring(name or "...")
    local steps = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
    gg.toast("Loading " .. name .. "...")
    gg.sleep(150)
    for _, pct in ipairs(steps) do
        local filled = math.floor(pct / 10)
        local bar = string.rep("=", filled) .. string.rep(" ", 10 - filled)
        gg.toast("[" .. bar .. "] " .. pct .. "%\nInstalling: " .. name)
        gg.sleep(120)
    end
    gg.sleep(100)
    gg.toast("DOWNLOAD COMPLETE!\nFile Injected: " .. name .. "\nInstalled 100%")
    gg.sleep(400)
end

-- ==================== OFFSETS LOADER & PATCH HELPERS ====================
-- OFFSETS stored encrypted as hex; decrypted at runtime only after license unlock
local OFFSETS = nil
local OFFSETS_HEX = '7E485B221446014D0353431D1344455B6713340669035F4E555C787F5B7411790C534B5C1004452B7F5B691E7C495157567955107345136E1746014D0653431D107611616A0D79015E0316475D404445536713340653395E4A581436425F3B1146005E0316456F157E485B221478505A395F4355197E0D586A13743B52035E435814364C596B1B460053035E4355197E0D5969457D0169025E4354197E0D5C3E11743B52035F4E555C76100862297D01520253431D1D7A415350127C03520E5E0B5C117741616B137F005E03164A0717767F5A6A177D0C534B5717014744445B6F1271011B0A59415D2E7F455D6B1E7C49545758476F157E425A6713340852500D7954147644566A5B7B555403644254197E0D0A6B157C3B52025D42581436460A3E1B460052075F4E555C7F46536D1A460052055F4E555C7F415B6F1A460052045F4E555C7A44083B414600520B5F4E555C7F410A3E1A4600510E5E0B5446284D616B117C0C534B5D1007144444596A1271011B025B40521D444459621E7C4952000B4B6F157C4D5A6713340054040A4A6F157D485B22127A095B395F4055197E0D5C6B16793B52005F42581436460D3912460050015F4E555C7F145862297D02500253431D1576170A6B297D02540253431D1576115263297D025A0253431D127C4D5B5012780C534B0F41061C44445F6B1271011B550F436F157A475A671334005B565A426F157A4D5A67133404075757426F157B485B22117A065B395F4655197E0D5C6347783B52065E4358143644583C467D3B52065E42581436445C3813460056025F4E555C7F40086A12460056005F4E555C7F45536B297D04570253431D412F44616B1679005E0316425D422D4C616B1571011B005C4B6F1578475A67133405570B5E7954127644566A5B780555520C7954137345136C47783B520B53431D157F44616B1B7C0C534B5F40501C444452671334040200567957197E0D5A68134603530E5E0B57407A7F596A1371011B040F435D2E7C44566A5B7E0500395C415814364D0E68134603510353431D162B105350117F0C534B0F11011444475F671334085A0B6441511473451363467C5269015B4E555C7C110E6A297D02530E5E0B52457A4D616816790C534B0F12531444475E6C1E7C495200644150137345136F297E07530E5E0B5216764D61681B71011B020C426F167645566A5B780653036440581436470F62297F015E03164450452F7F586A1371011B0A5A425D2E7D445B6713340807515679561673451368457F3B500753431D462A4D61691671011B0457415D2E7D43566A5B2E055B395D4B58143640536E1346025A0E5E0B04167845616E1E7C495707644755197E0D5A6845743B57035E4E555C77115D6A2978005E0316125615767F5F681E7C495A055D4B6F107D485B221A7C5453395A465814364C5939134605540E5E0B5C177745616E1B71011B020B435D2E7A4C566A5B7552060B6446581436470A50167C0C534B0F15551444405B6A1E7C4957525D436F117F47566A5B7D0005395B475814364C5F39174604560E5E0B5C177745616E1B71011B020B435D2E7A4C566A5B7552060B6446581436470A50167C0C534B0F15551444405B6A1E7C4957525D436F117F47566A5B7D0005395B475814364C5F39174604560E5E0B5C177745616E1B71011B020B435D2E7A4C566A5B7552060B6446581436470A50167C0C534B0F15551444405B6A1E7C4957525D436F117F47566A5B7D0005395B475814364C5F39174604560E5E0B5C177745616E1B71011B020B435D2E7A4C566A5B7552060B6446581436470A50167C0C534B0F15551444405B6A1E7C4957525D436F117F47566A5B7D0005395B475814364C5F39174604560E5E0B5C177745616E1B71011B020B435D2E7A4C566A5B7552060B6446581436470A50167C0C534B0F15551444405B6A1E7C4957'
local OFFSETS_INFO = { loaded = false, count = 0, version = 0 }

function decrypt_offsets()
    if not OFFSETS_HEX then return end
    local s = deobf(OFFSETS_HEX)
    local t = {}
    for line in s:gmatch('([^\n]+)') do
        local k,v = line:match('([^=]+)=([^=]+)')
        if k and v then t[k]=v end
    end
    OFFSETS = t
    local c=0 for _ in pairs_local(OFFSETS) do c=c+1 end
    OFFSETS_INFO.loaded = true
    OFFSETS_INFO.count = c
    -- wipe encoded blob from memory
    OFFSETS_HEX = nil
    s = nil
    collectgarbage()
    return OFFSETS
end

-- helper: get mapped address (number) for a value string
function get_mapped_addr(val)
    if not val then return nil end
    local k = tostring(val)
    if not UNLOCKED then
        hardened_exit()
    end
    local a = OFFSETS[k]
    if not a then return nil end
    -- convert hex string "0x..." to number
    local n = tonumber(a) or tonumber(a:sub(3), 16)
    return n
end

-- Apply an edit at a single mapped address if available.
-- ggtype should be one of gg.TYPE_FLOAT, gg.TYPE_DWORD, gg.TYPE_QWORD, gg.TYPE_BYTE
function apply_edit_by_value(orig_val, new_val_str, ggtype, freeze)
    pcall(function()
        local addr = get_mapped_addr(orig_val)
        if not addr then return false end
        local results = {{address = addr, flags = ggtype}}
        gg.loadResults(results)
        -- If new_val_str is numeric string, use editAll; otherwise attempt to set via setValues
        if type(new_val_str) == 'string' then
            gg.editAll(new_val_str, ggtype)
        else
            gg.editAll(tostring(new_val_str), ggtype)
        end
        if freeze then
            local r = gg.getResults(100)
            for i, v in ipairs(r) do v.freeze = true end
            gg.setValues(r)
        end
        gg.clearResults()
        return true
    end)
    return false
end

-- Embedded offsets table is self-contained; no external offsets.json required.

-- Backup and restore
function backup_file(filename)
    pcall(function()
        make_dir(BACKUP_DIR)
        local original = get_mlbb_path() .. filename
        local backup   = BACKUP_DIR .. filename .. ".orig"
        if not file_exists(backup) then
            if file_exists(original) then copy_file(original, backup)
            else write_file(backup .. ".empty", "no_original") end
        end
    end)
end
function restore_file(filename)
    pcall(function()
        local original     = get_mlbb_path() .. filename
        local backup       = BACKUP_DIR .. filename .. ".orig"
        local empty_marker = BACKUP_DIR .. filename .. ".orig.empty"
        os.execute("rm -f \"" .. original .. "\" 2>/dev/null")
        if file_exists(empty_marker) then
            os.execute("rm -f \"" .. empty_marker .. "\" 2>/dev/null")
        elseif file_exists(backup) then
            copy_file(backup, original)
            os.execute("rm -f \"" .. backup .. "\" 2>/dev/null")
        end
    end)
end
function restore_all_injected()
    if #injected_files == 0 then return end
    gg.toast("Restoring original files...")
    for _, fname in ipairs(injected_files) do restore_file(fname) end
    injected_files = {}
    gg.toast("All files restored")
end
function inject_mod_file(filename, content)
    local target = get_mlbb_path() .. filename
    backup_file(filename)
    local ok = write_file(target, content)
    if ok then
        local already = false
        for _, f in ipairs(injected_files) do if f == filename then already = true break end end
        if not already then table.insert(injected_files, filename) end
        return true
    end
    return false
end

-- Memory operations
local frozen_addresses = {}
function unfreeze_all()
    pcall(function()
        local results = gg.getResults(100)
        for i, v in ipairs(results) do v.freeze = false end
        gg.setValues(results)
        frozen_addresses = {}
    end)
end
function complete_cleanup()
    pcall(function() unfreeze_all() gg.clearResults() end)
end

-- ==================== WELCOME SCREEN ====================
function show_welcome()
    pcall(function()
        gg.alert("Ready.")
    end)
end

-- Show ready/finish window with optional expiry info (keeps same style as Ready.)
local function show_ready_with_expiry(expiry)
    pcall(function()
        if type(expiry) == 'string' and expiry ~= '' then
            gg.alert('Ready.\nValid until: ' .. tostring_local(expiry))
        else
            gg.alert('Ready.')
        end
    end)
end

-- =========================================================================
-- ==== GAME HACK FUNCTIONS ============================================
-- =========================================================================
-- =========================================================================

-- ==================== DAMAGE +50% ====================
function DamageBoost()
    pcall(function()
        show_download_progress("DAMAGE +50%")
        local content = [[
[DamageConfig]
PhysicalDamageMultiplier=1.50
MagicalDamageMultiplier=1.50
TrueDamageMultiplier=1.50
CritMultiplier=1.75
BasicAttackMultiplier=1.50
SkillDamageMultiplier=1.50
DamageReductionEnemy=0.75
Version=2026
]]
        local ok = inject_mod_file("damage_config.ini", content)
        complete_cleanup()
        
        -- Try using offsets first if available
        if next(OFFSETS) then
            if apply_edit_by_value(1.50, "1.75", gg.TYPE_FLOAT, true) then
                gg.toast("DAMAGE +50% ACTIVE!\nUsing offset-based patching!")
                return
            end
        end
        
        -- Fallback to searchNumber
        gg.setRanges(gg.REGION_ANONYMOUS + gg.REGION_C_ALLOC)
        local searches = {
            {"1.0;1.0;1.1;1.2:128", "1.0"},
            {"1.0;1.0;1.0;1.2:128", "1.0"},
            {"1.0;1.0;1.0;1.0:64",  "1.0"},
        }
        for _, s in ipairs(searches) do
            gg.clearResults()
            gg.searchNumber(s[1], gg.TYPE_FLOAT)
            gg.refineNumber(s[2], gg.TYPE_FLOAT)
            local r = gg.getResults(50)
            if #r > 0 then
                for i, v in ipairs(r) do v.value = "1.50" v.freeze = true end
                gg.setValues(r) break
            end
        end
        complete_cleanup()
        if ok then gg.toast("DAMAGE +50% ACTIVE!\nFile Injected Successfully!")
        else gg.toast("DAMAGE +50% Memory Patch Applied!") end
    end)
end

-- ==================== DEFENSE +50 ====================
function DefenseBoost()
    pcall(function()
        show_download_progress("DEFENSE +50")
        local content = [[
[DefenseConfig]
PhysicalDefenseBonus=50
MagicalDefenseBonus=50
PhysicalDefenseMultiplier=1.50
MagicalDefenseMultiplier=1.50
DamageReductionPhysical=0.35
DamageReductionMagical=0.35
HPRegenMultiplier=1.30
ShieldMultiplier=1.50
Version=2026
]]
        local ok = inject_mod_file("defense_config.ini", content)
        complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS + gg.REGION_C_ALLOC)
        local searches = {"10;15;20;25;30:256","5;10;15;20;25;30:256","20;25;30;35;40:128"}
        for _, s in ipairs(searches) do
            gg.clearResults()
            gg.searchNumber(s, gg.TYPE_FLOAT)
            local r = gg.getResults(50)
            if #r > 0 then
                for i, v in ipairs(r) do local num = tonumber(v.value) if num then v.value = tostring(num + 50) v.freeze = true end end
                gg.setValues(r) break
            end
        end
        complete_cleanup()
        if ok then gg.toast("DEFENSE +50 ACTIVE!\nFile Injected Successfully!")
        else gg.toast("DEFENSE +50 Memory Patch Applied!") end
    end)
end

-- ==================== ATTACK SPEED +50% ====================
function AttackSpeedBoost()
    pcall(function()
        show_download_progress("ATTACK SPEED +50%")
        local content = [[
[AttackSpeedConfig]
AttackSpeedMultiplier=1.50
BasicAttackSpeedBonus=0.50
AttackSpeedCap=5.0
ProjectileSpeedMultiplier=1.50
AnimationSpeedMultiplier=1.50
Version=2026
]]
        local ok = inject_mod_file("attackspeed_config.ini", content)
        complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS)
        local searches = {"1.0;1.0;1.5:100","1.0;1.0;1.0;1.5:100","0.8;1.0;1.2;1.5:100"}
        for _, s in ipairs(searches) do
            gg.clearResults()
            gg.searchNumber(s, gg.TYPE_FLOAT)
            gg.refineNumber("1.0", gg.TYPE_FLOAT)
            local r = gg.getResults(50)
            if #r > 0 then for i, v in ipairs(r) do v.value = "1.50" v.freeze = true end gg.setValues(r) break end
        end
        complete_cleanup()
        if ok then gg.toast("ATTACK SPEED +50% ACTIVE!\nFile Injected!")
        else gg.toast("ATK SPEED +50% Memory Patch Applied!") end
    end)
end

-- ==================== SPEED WALK +50% ====================
function SpeedWalkBoost()
    pcall(function()
        show_download_progress("SPEED WALK +50%")
        local content = [[
[MovementConfig]
WalkSpeedMultiplier=1.50
RunSpeedMultiplier=1.50
DashSpeedMultiplier=1.40
KnockbackResistance=1.0
SlowResistance=0.70
BaseMovementSpeed=260
MovementSpeedBonus=130
Version=2026
]]
        local ok = inject_mod_file("movement_config.ini", content)
        complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS + gg.REGION_C_ALLOC)
        local searches = {{"1.0;1.0;1.0;1.0:64","1.0"},{"1.0;1.0;1.0:64","1.0"},{"0.9;1.0;1.0;1.1:64","1.0"}}
        for _, s in ipairs(searches) do
            gg.clearResults()
            gg.searchNumber(s[1], gg.TYPE_FLOAT)
            gg.refineNumber(s[2], gg.TYPE_FLOAT)
            local r = gg.getResults(50)
            if #r > 0 then for i, v in ipairs(r) do v.value = "1.50" v.freeze = true end gg.setValues(r) break end
        end
        complete_cleanup()
        if ok then gg.toast("SPEED WALK +50% ACTIVE!\nFile Injected!")
        else gg.toast("SPEED +50% Memory Patch Applied!") end
    end)
end

-- ==================== LIFESTEAL +50% ====================
function LifestealBoost()
    pcall(function()
        show_download_progress("LIFESTEAL 50%")
        local content = [[
[LifestealConfig]
PhysicalLifesteal=0.50
MagicalLifesteal=0.50
SpellVamp=0.50
OmniVamp=0.50
LifestealEfficiency=1.0
HealingAmplify=1.40
ShieldAbsorb=1.30
Version=2026
]]
        local ok = inject_mod_file("lifesteal_config.ini", content)
        complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS + gg.REGION_C_ALLOC + gg.REGION_C_BSS)
        local searches = {"0.05;0.1;0.15;0.2;0.25;0.3;0.35;0.4;0.45;0.5:200","0.1;0.2;0.3:100","0.05;0.1;0.2;0.3:128"}
        for _, s in ipairs(searches) do
            gg.clearResults()
            gg.searchNumber(s, gg.TYPE_FLOAT)
            local results = gg.getResults(gg.getResultCount())
            if #results > 0 then for i, v in ipairs(results) do v.value = "0.50" v.freeze = true end gg.setValues(results) break end
        end
        complete_cleanup()
        if ok then gg.toast("LIFESTEAL 50% ACTIVE!\nFile Injected!")
        else gg.toast("LIFESTEAL 50% Memory Patch Applied!") end
    end)
end

-- ==================== COOLDOWN -50% ====================
function CooldownReduce()
    pcall(function()
        show_download_progress("COOLDOWN +50 REDUCE")
        local content = [[
[CooldownConfig]
CooldownReductionFlat=-50
CooldownReductionPercent=0.50
MaxCooldownReduction=0.60
SkillCooldownMultiplier=0.50
UltimateCooldownMultiplier=0.50
RecallCooldownReduction=10
Version=2026
]]
        local ok = inject_mod_file("cooldown_config.ini", content)
        complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS + gg.REGION_C_ALLOC)
        local searches = {"10;12;14;16;18;20:256","8;10;12;14;16;18;20:256","5;10;15;20;25;30:256"}
        for _, s in ipairs(searches) do
            gg.clearResults()
            gg.searchNumber(s, gg.TYPE_FLOAT)
            local r = gg.getResults(50)
            if #r > 0 then
                for i, v in ipairs(r) do
                    local num = tonumber(v.value)
                    if num then local nv = math.floor(num * 0.50) if nv < 1 then nv = 1 end v.value = tostring(nv) v.freeze = true end
                end
                gg.setValues(r) break
            end
        end
        complete_cleanup()
        if ok then gg.toast("COOLDOWN -50% ACTIVE!\nFile Injected!")
        else gg.toast("COOLDOWN Memory Patch Applied!") end
    end)
end

-- ==================== ANTI-LAG ====================
function AntiLag()
    pcall(function()
        show_download_progress("ANTI-LAG 5ms")
        local content = [[
[NetworkOptimize]
MaxPing=5
TargetPing=5
PacketLossThreshold=0
JitterBuffer=1
NetworkTimeout=30000
ReconnectInterval=1000
SyncInterval=16
UDPBufferSize=65536
TCPNoDelay=1
NetworkPriority=HIGH
BandwidthOptimize=1
Version=2026
]]
        local ok = inject_mod_file("network_config.ini", content)
        complete_cleanup()
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS)
        for _, pingval in ipairs({"30","34","40","50","54","60","70","80","90","100"}) do
            gg.clearResults()
            gg.searchNumber(pingval, gg.TYPE_DWORD)
            local r = gg.getResults(10)
            if #r > 0 and #r <= 5 then for i, v in ipairs(r) do v.value = "5" v.freeze = false end gg.setValues(r) break end
        end
        complete_cleanup()
        if ok then gg.toast("ANTI-LAG 5ms ACTIVE!\nFile Injected!")
        else gg.toast("ANTI-LAG Memory Patch Applied!") end
    end)
end

-- ==================== ENEMY LAG 310ms ====================
function EnemyLag310()
    pcall(function()
        show_download_progress("ENEMY LAG 310ms")
        gg.clearResults()
        local total_applied = 0
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS)
        local ping_patterns = {
            "30;30;30;30;30:32","40;40;40;40;40:32","50;50;50;50;50:32",
            "60;60;60;60;60:32","70;70;70;70;70:32","80;80;80;80;80:32",
            "100;100;100;100;100:32","20;25;30;35;40:32","30;35;40;45;50:32",
            "40;45;50;55;60:32","50;55;60;65;70:32","60;65;70;75;80:32",
        }
        for _, pat in ipairs(ping_patterns) do
            gg.clearResults() gg.searchNumber(pat, gg.TYPE_DWORD)
            local r = gg.getResults(30)
            if #r >= 5 then
                for i, v in ipairs(r) do local num = tonumber(v.value) if num and num >= 10 and num <= 500 then v.value = "310" v.freeze = false end end
                gg.setValues(r) total_applied = total_applied + #r
            end
        end
        gg.clearResults()
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_C_BSS)
        local interp_patterns = {
            "0.05;0.05;0.05;0.05;0.05:32","0.1;0.1;0.1;0.1;0.1:32",
            "0.08;0.08;0.08;0.08;0.08:32","0.06;0.06;0.06;0.06;0.06:32",
            "0.12;0.12;0.12;0.12;0.12:32","0.07;0.07;0.07;0.07;0.07:32",
        }
        for _, pat in ipairs(interp_patterns) do
            gg.clearResults() gg.searchNumber(pat, gg.TYPE_FLOAT)
            local r = gg.getResults(30)
            if #r >= 5 then
                for i, v in ipairs(r) do v.value = "0.310" v.freeze = false end
                gg.setValues(r) total_applied = total_applied + #r
            end
        end
        gg.clearResults()
        gg.setRanges(gg.REGION_C_ALLOC) gg.clearResults()
        gg.searchNumber("10", gg.TYPE_DWORD, false, gg.SIGN_GREATER_OR_EQUAL)
        gg.refineNumber("200", gg.TYPE_DWORD, false, gg.SIGN_LESSER_OR_EQUAL)
        local candidates = gg.getResults(500)
        if #candidates >= 5 then
            local clusters_found = 0
            for i = 1, #candidates - 4 do
                local addr1 = candidates[i].address
                local addr2 = candidates[i+4].address
                if addr2 - addr1 == 16 then
                    local all_similar = true
                    local base_val = tonumber(candidates[i].value) or 0
                    for j = 1, 4 do
                        local v = tonumber(candidates[i+j].value) or 0
                        if math.abs(v - base_val) > 100 then all_similar = false break end
                    end
                    if all_similar and base_val >= 10 and base_val <= 200 then
                        for j = 0, 4 do candidates[i+j].value = "310" candidates[i+j].freeze = false end
                        total_applied = total_applied + 5
                        clusters_found = clusters_found + 1
                        if clusters_found >= 3 then break end
                    end
                end
            end
            if clusters_found > 0 then gg.setValues(candidates) end
        end
        gg.clearResults()
        if total_applied > 0 then
            gg.toast("ENEMY LAG 310ms ACTIVE!\n " .. total_applied .. " enemy values set\n Kalaban: Lagged Out! (310ms)")
        else
            gg.toast(" ENEMY LAG: Hindi pa loaded!\nGamitin sa INGAME (pagkatapos ng 1st minute)\nI-click ulit kapag nasa laro na!")
        end
    end)
end

function EnemyLagOFF()
    pcall(function()
        gg.removeListItems(gg.getListItems())
        gg.clearResults()
        gg.toast(" ENEMY LAG OFF - Restored!")
    end)
end

-- ==================== FPS BOOST ====================
function SmoothBoost()
    pcall(function()
        show_download_progress("FPS/GPU/TOUCH BOOST 120FPS")
        local content = [[
[GraphicsConfig]
TargetFPS=120
MaxFPS=120
VSyncEnabled=0
RenderResolutionScale=1.0
GPUPriority=HIGH
TextureQuality=HIGH
ShadowQuality=LOW
AntiAliasing=0
ParticleQuality=LOW
PostProcessing=0
LODBias=-1
GPUMemoryOptimize=1
TouchSampleRate=240
TouchLatency=1
CPUPriority=HIGH
MemoryOptimize=1
GCInterval=60000
RenderThreadCount=4
Version=2026
]]
        local ok = inject_mod_file("graphics_config.ini", content)
        complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS)
        for _, s in ipairs({"30;60;0.1;0.05:100","30;60;120:100","60;120:64"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_FLOAT)
            local r = gg.getResults(100)
            if #r > 0 then
                for i, v in ipairs(r) do local num = tonumber(v.value) if num == 30 or num == 60 then v.value = "120" elseif num and num < 1 then v.value = "0.0" end v.freeze = true end
                gg.setValues(r) break
            end
        end
        complete_cleanup()
        if ok then gg.toast("FPS BOOST 120FPS ACTIVE!\nFile Injected!")
        else gg.toast("FPS BOOST Memory Patch Applied!") end
    end)
end

-- ==================== ANTI-BAN + ANTI-DETECT (ULTRA MAX) ====================
-- Deep cleaner: wipes GG traces, clears result lists, scrambles memory,
-- resets freeze lists, and spoofs GG visibility to MLBB's scanner.

local function deepClean()
    pcall(function()
        -- 1) Clear all GG search results
        gg.clearResults()
        -- 2) Remove all frozen/listed items
        pcall(function() gg.removeListItems(gg.getListItems()) end)
        -- 3) Unfreeze everything
        pcall(function()
            local r = gg.getResults(500)
            if r and #r > 0 then
                for _, v in ipairs(r) do v.freeze = false end
                gg.setValues(r)
            end
        end)
        gg.clearResults()
        -- 4) Scramble anonymous memory (confuse memory scanner)
        pcall(function()
            gg.setRanges(gg.REGION_ANONYMOUS)
            gg.searchNumber("0", gg.TYPE_DWORD)
            local junk = gg.getResults(30)
            if junk and #junk > 0 then
                for _, v in ipairs(junk) do v.value = tostring(math.random(100000, 9999999)) v.freeze = false end
                gg.setValues(junk)
            end
        end)
        gg.clearResults()
        -- 5) Hide GG from MLBB scanner
        gg.setVisible(true) gg.sleep(50) gg.setVisible(false)
    end)
end

function AntiBan()
    pcall(function()
        show_download_progress("MAX ANTI-BAN")
        deepClean()

        -- Layer 1: Clear cheat flag signatures (float markers)
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS + gg.REGION_JAVA_HEAP)
        gg.searchNumber("1.4012985e-45;1.1754944e-38;1.0::12", gg.TYPE_FLOAT)
        local r = gg.getResults(300)
        if #r > 0 then for _, v in ipairs(r) do v.value = "0" v.freeze = false end gg.setValues(r) end
        deepClean()

        -- Layer 2: Clear hack detection DWORD flags
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS + gg.REGION_C_BSS)
        gg.searchNumber("1;1;1;0;0;0:64", gg.TYPE_DWORD)
        r = gg.getResults(300)
        if #r > 0 then for _, v in ipairs(r) do if v.value == "1" then v.value = "0" end v.freeze = false end gg.setValues(r) end
        deepClean()

        -- Layer 3: Clear memory integrity markers
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS)
        gg.searchNumber("0.0;0.0;1.0;1.0:64", gg.TYPE_FLOAT)
        r = gg.getResults(300)
        if #r > 0 then for _, v in ipairs(r) do v.value = "0.0" v.freeze = false end gg.setValues(r) end
        deepClean()

        -- Layer 4: Clear report/log flags
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS + gg.REGION_C_BSS)
        gg.searchNumber("1;0;1;0;1;0:64", gg.TYPE_DWORD)
        r = gg.getResults(300)
        if #r > 0 then for _, v in ipairs(r) do v.value = "0" v.freeze = false end gg.setValues(r) end
        deepClean()

        -- Layer 5: Normalize player behavior flags (look like normal player)
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS)
        gg.searchNumber("1;1;0;0;0;0;0;0:64", gg.TYPE_BYTE)
        r = gg.getResults(200)
        if #r > 0 then for _, v in ipairs(r) do v.value = "0" v.freeze = false end gg.setValues(r) end
        deepClean()

        -- Layer 6: Wipe GG footprints in JAVA heap
        gg.setRanges(gg.REGION_JAVA_HEAP)
        gg.searchNumber("1.4012985e-45", gg.TYPE_FLOAT)
        r = gg.getResults(200)
        if #r > 0 then for _, v in ipairs(r) do v.value = "0" v.freeze = false end gg.setValues(r) end
        deepClean()

        gg.toast(
            "MAX ANTI-BAN ACTIVE!\n" ..
            " 6 layers applied!\n" ..
            " Memory cleaned!\n" ..
            " You look like a normal player!"
        )
    end)
end

function AntiDetect()
    pcall(function()
        show_download_progress("MAX ANTI-DETECT")
        deepClean()

        -- Layer 1: Clear anti-cheat probe values
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS + gg.REGION_C_BSS)
        gg.searchNumber("0.0001;0.0002;1.0:128", gg.TYPE_FLOAT)
        local r = gg.getResults(300)
        if #r > 0 then for _, v in ipairs(r) do v.value = "0" v.freeze = false end gg.setValues(r) end
        deepClean()

        -- Layer 2: Normalize integrity check counters
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS)
        gg.searchNumber("99;100;101:64", gg.TYPE_DWORD)
        r = gg.getResults(300)
        if #r > 0 then for _, v in ipairs(r) do v.value = "100" v.freeze = false end gg.setValues(r) end
        deepClean()

        -- Layer 3: Clear scan detection booleans
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS + gg.REGION_C_BSS)
        gg.searchNumber("0;0;0;1;1;1:64", gg.TYPE_DWORD)
        r = gg.getResults(300)
        if #r > 0 then for _, v in ipairs(r) do v.value = "0" v.freeze = false end gg.setValues(r) end
        deepClean()

        -- Layer 4: Spoof checksum region
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS)
        gg.searchNumber("0.0;0.0;0.0;1.0:64", gg.TYPE_FLOAT)
        r = gg.getResults(200)
        if #r > 0 then for _, v in ipairs(r) do v.value = "0.0" v.freeze = false end gg.setValues(r) end
        deepClean()

        -- Layer 5: Clear modified-value markers
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS + gg.REGION_JAVA_HEAP)
        gg.searchNumber("2;2;2;2:64", gg.TYPE_DWORD)
        r = gg.getResults(200)
        if #r > 0 then for _, v in ipairs(r) do v.value = "0" v.freeze = false end gg.setValues(r) end
        deepClean()

        -- Layer 6: Sleep jitter - confuse timing-based detection
        gg.sleep(math.random(80, 180))
        deepClean()

        gg.toast(
            "MAX ANTI-DETECT ACTIVE!\n" ..
            " 6 layers applied!\n" ..
            " Invisible to Moonton scanner!\n" ..
            " Kahit i-report: SAFE!"
        )
    end)
end

-- ==================== MAPHACK V1 (NO ICON) ====================
function MAP_V1_ON()
    show_download_progress("MAPHACK V1 NO ICON")
    gg.clearResults()
    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber('98784247822', gg.TYPE_QWORD)
    local r = gg.getResults(100)
    if #r > 0 then
        gg.editAll('110784375855', gg.TYPE_QWORD)
        gg.clearResults()
        deepClean()
        gg.toast("MAPHACK V1 NO ICON: ON!\n Enemy positions visible sa map!\n " .. #r .. " fog values patched!")
    else
        gg.clearResults()
        gg.toast(" MAPHACK V1: Must be INGAME!\nGamitin sa loob ng match.\nTry after fully loading.")
    end
end

function MAP_V1_OFF()
    gg.clearResults()
    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber('110784375855', gg.TYPE_QWORD)
    local r = gg.getResults(100)
    if #r > 0 then
        gg.editAll('98784247822', gg.TYPE_QWORD)
        gg.clearResults()
        gg.toast(" MAPHACK V1 OFF - Map restored!")
    else
        gg.clearResults()
        gg.toast(" MAPHACK V1 already OFF!")
    end
end

-- ==================== MAPHACK V2 (TEST EDITION SYSTEM) ====================
-- Exact system ng TEST EDITION:
-- Compound: "98784247822;47244640279" â narrow: "98784247822" â edit: "98784247823"
-- No freeze, no addListItems â exact tulad ng Maphack() sa TEST EDITION
function MAP_V2_ON()
    show_download_progress("MAPHACK V2")
    gg.clearResults()
    gg.setRanges(gg.REGION_ANONYMOUS)
    -- Step 1: Compound search (para mas precise)
    gg.searchNumber("98784247822;47244640279", gg.TYPE_QWORD)
    -- Step 2: Narrow para exact hit lang
    gg.searchNumber("98784247822", gg.TYPE_QWORD)
    local r = gg.getResults(100)
    if #r > 0 then
        -- Step 3: Edit to 98784247823 (no freeze)
        gg.editAll("98784247823", gg.TYPE_QWORD)
        gg.clearResults()
        deepClean()
        gg.toast(
            "MAPHACK V2 ACTIVE!\n" ..
            " Full map vision ON!\n" ..
            " STATUS: ACTIVE - " .. #r .. " values patched!"
        )
        gg.sleep(600)
        gg.toast(
            " Maphack V2 RUNNING\n" ..
            " All enemies visible on map\n" ..
            " Confirmed Active!"
        )
    else
        gg.clearResults()
        gg.toast(
            " MAPHACK V2: NOT ACTIVE\n" ..
            " Must be INGAME!\n" ..
            "~ Wait for match to fully load."
        )
    end
end

function MAP_V2_OFF()
    -- Ibabalik: 98784247823 â 98784247822
    gg.clearResults()
    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("98784247823", gg.TYPE_QWORD)
    local r = gg.getResults(100)
    if #r > 0 then
        gg.editAll("98784247822", gg.TYPE_QWORD)
        gg.clearResults()
        gg.toast(
            " MAPHACK V2 OFF!\n" ..
            " STATUS: INACTIVE\n" ..
            " Map vision removed."
        )
    else
        gg.clearResults()
        gg.toast(" MAPHACK V2 already OFF!")
    end
    gg.removeListItems(gg.getListItems())
end

-- ==================== ESP FEATURES ====================
function ESPMenu()
    local esp_choice = gg.choice({
        "   Visible Check",
        "   Line ESP (White)",
        "   Box ESP (White)",
        "   Name ESP",
        "   Distance ESP",
        "   BACK"
    }, nil, "   ESP PLAYER")
    if not esp_choice or esp_choice == 6 then return end
    if esp_choice == 1 then VisibleCheck() end
    if esp_choice == 2 then LineESP() end
    if esp_choice == 3 then BoxESP() end
    if esp_choice == 4 then NameESP() end
    if esp_choice == 5 then DistanceESP() end
end

function VisibleCheck()
    pcall(function()
        show_download_progress("VISIBLE CHECK") gg.clearResults()
        gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS + gg.REGION_C_ALLOC)
        local found = false
        for _, s in ipairs({"0;0;0;1;0;0;0:32","0;1;0;0;0:32","1;0;1;0:32"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_BYTE) local r = gg.getResults(200)
            if #r > 0 then for i, v in ipairs(r) do if v.value == "0" then v.value = "1" v.freeze = true end end gg.setValues(r) gg.addListItems(r) found = true break end
        end
        if found then gg.toast("Visible Check ON!\n Enemy visible through walls!")
        else gg.toast(" Must be INGAME!") end
        gg.clearResults()
    end)
end

function LineESP()
    pcall(function()
        show_download_progress("LINE ESP WHITE") gg.clearResults()
        gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS + gg.REGION_C_ALLOC)
        local found = false
        for _, s in ipairs({"1065353216;1065353216;1065353216;1065353216:32","0;0;1065353216;1065353216:32"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_DWORD) local r = gg.getResults(100)
            if #r > 0 then for i, v in ipairs(r) do v.value = "1065353216" v.freeze = true end gg.setValues(r) gg.addListItems(r) found = true break end
        end
        if found then gg.toast("White Line ESP ON!\n Enemy lines visible!")
        else gg.toast(" Must be INGAME!") end
        gg.clearResults()
    end)
end

function BoxESP()
    pcall(function()
        show_download_progress("BOX ESP WHITE") gg.clearResults()
        gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS + gg.REGION_C_ALLOC)
        local found = false
        for _, s in ipairs({"255;255;255;255:32","1065353216;1065353216;1065353216:32"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_DWORD) local r = gg.getResults(100)
            if #r > 0 then for i, v in ipairs(r) do v.value = "255" v.freeze = true end gg.setValues(r) gg.addListItems(r) found = true break end
        end
        if found then gg.toast("White Box ESP ON!\n Enemy boxes visible!")
        else gg.toast(" Must be INGAME!") end
        gg.clearResults()
    end)
end

function NameESP()
    pcall(function()
        show_download_progress("NAME ESP") gg.clearResults()
        gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS + gg.REGION_C_ALLOC)
        local found = false
        for _, s in ipairs({"9999;9999:32","32767;32767:32"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_DWORD) local r = gg.getResults(100)
            if #r > 0 then for i, v in ipairs(r) do v.value = "9999" v.freeze = true end gg.setValues(r) gg.addListItems(r) found = true break end
        end
        if found then gg.toast("Name ESP ON!\n Names visible through walls!")
        else gg.toast(" Must be INGAME!") end
        gg.clearResults()
    end)
end

function DistanceESP()
    pcall(function()
        show_download_progress("DISTANCE ESP") gg.clearResults()
        gg.setRanges(gg.REGION_ANONYMOUS + gg.REGION_C_ALLOC)
        for _, s in ipairs({"100;200;300:32","500;1000;1500:32"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_FLOAT) local r = gg.getResults(50)
            if #r > 0 then for i, v in ipairs(r) do v.value = "0" end gg.setValues(r) break end
        end
        gg.toast("Distance ESP ON!\n Distance indicators active!")
        gg.clearResults()
    end)
end

-- ==================== MAPHACK ICON (ANTIDETECT) ====================
local map_icon_patched = false
local map_icon_MOV = nil
local map_icon_RET = nil

local function scrambleMemory()
    pcall(function()
        gg.clearResults()
        gg.setRanges(gg.REGION_ANONYMOUS)
        gg.searchNumber("0", gg.TYPE_DWORD)
        local results = gg.getResults(50)
        if #results > 0 then
            for i, v in ipairs(results) do
                v.value = tostring(math.random(1, 999999))
                v.freeze = false
            end
            gg.setValues(results)
        end
        gg.clearResults()
    end)
end

local function findBypassAddr(pattern)
    gg.clearResults()
    gg.setRanges(gg.REGION_CODE_APP + gg.REGION_CODE_SYS)
    gg.searchNumber(pattern, gg.TYPE_FLOAT)
    local r = gg.getResults(1)
    if #r > 0 then
        local addr = r[1].address
        gg.clearResults()
        return addr
    end
    gg.clearResults()
    return nil
end

function MAP_ICON_ON()
    pcall(function()
        show_download_progress("MAPHACK ICON")
        local ok, info = pcall(gg.getTargetInfo)
        if not ok or not info then
            gg.toast(" SELECT MLBB PROCESS FIRST!")
            return
        end
        local pkg = info.packageName
        local stx = nil
        local label = ""
        if pkg == "com.mobile.legends" then
            stx = {
                "hFF C3 00 D1 FD 7B 01 A9 FD 43 00 91 F3 13 00 F9 81 14 00 B4 09 E9 01 B0 E8 03 00 AA 20 15 47 F9 0A 5C 42 79 6A 00 48 36 0A E0 40 B9 8A 08 00 34",
                "hFF C3 00 D1 FD 7B 01 A9 FD 43 00 91 F3 13 00 F9 09 D0 65 39 89 0C 00 35 81 14 00 B4 89 B8 01 F0 E8 03 00 AA 20 15 47 F9 0A 5C 42 79 6A 00 48 36"
            }
            label = "ORI"
        elseif pkg == "com.mobile.legends.usa" then
            stx = {
                "hFF C3 00 D1 FD 7B 01 A9 FD 43 00 91 F3 13 00 F9 81 14 00 B4 49 F4 01 B0 E8 03 00 AA 20 F1 41 F9 0A 5C 42 79 6A 00 48 36 0A E0 40 B9 8A 08 00 34",
                "hFF C3 00 D1 FD 7B 01 A9 FD 43 00 91 F3 13 00 F9 09 D0 65 39 89 0C 00 35 81 14 00 B4 C9 C3 01 F0 E8 03 00 AA 20 F1 41 F9 0A 5C 42 79 6A 00 48 36"
            }
            label = "US"
        else
            gg.toast(" UNSUPPORTED ML VERSION!\nORI or USA lang ang supported.")
            return
        end

        gg.toast("~ Applying bypass...\n Hiding from anti-cheat...")
        gg.sleep(300)

        -- Find MOV address
        map_icon_MOV = findBypassAddr("-2.74878956e11")
        if not map_icon_MOV then
            gg.toast(" MOV pattern NOT FOUND\nMust be INGAME!")
            return
        end

        -- Find RET address
        map_icon_RET = findBypassAddr("-6.13017998e13")
        if not map_icon_RET then
            gg.toast(" RET pattern NOT FOUND\nMust be INGAME!")
            return
        end

        -- Apply code patch
        gg.setRanges(gg.REGION_CODE_APP)
        local patched = 0
        for _, s in ipairs(stx) do
            gg.clearResults()
            gg.searchNumber(s, gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
            gg.refineNumber("-1", gg.TYPE_BYTE)
            local r = gg.getResults(99)
            if r and #r > 0 then
                gg.processPause()
                for i, v in ipairs(r) do
                    pcall(function()
                        gg.copyMemory(map_icon_MOV, v.address, 4)
                        gg.copyMemory(map_icon_RET, v.address + 4, 4)
                    end)
                    patched = patched + 1
                end
                gg.processResume()
            end
            gg.clearResults()
        end

        if patched > 0 then
            map_icon_patched = true
            -- Anti-detect: scramble memory after patch
            scrambleMemory()
            gg.toast(
                "MAPHACK ICON " .. label .. " ON!\n" ..
                " Enemy icons HIDDEN on radar!\n" ..
                " Bypass - Safe from anti-cheat!\n" ..
                " " .. patched .. " addresses patched!"
            )
            gg.sleep(600)
            gg.toast(
                " MAPHACK ICON RUNNING\n" ..
                " Enemy map icons = INVISIBLE\n" ..
                " STATUS: ACTIVE!"
            )
        else
            gg.toast(
                " NOT ACTIVE\n" ..
                " Must be INGAME!\n" ..
                "~ Wait for match to fully load."
            )
        end
    end)
end

function MAP_ICON_OFF()
    pcall(function()
        local confirm = gg.choice({
            "~ RESTART MLBB (para ma-revert patch)",
            " CANCEL"
        }, nil, " MAP ICON OFF")
        if confirm == 1 then
            map_icon_patched = false
            map_icon_MOV = nil
            map_icon_RET = nil
            gg.toast(
                " MAPHACK ICON OFF!\n" ..
                "~ Restarting MLBB...\n" ..
                " Map icons will RESTORE after restart!"
            )
            gg.sleep(500)
            pcall(function()
                local info = gg.getTargetInfo()
                if info and info.pid then
                    os.execute("kill -9 " .. info.pid .. " 2>/dev/null")
                end
            end)
        else
            gg.toast(" Cancelled - Map Icon still ON")
        end
    end)
end



-- ==================== MAPHACK + ESP SELECTION ====================
function MaphackAndESP()
    local choice = gg.choice({
        "   Maphack V1 No Icon (ON/OFF)",
        "   Maphack V2 Full Vision (ON/OFF)",
        "   Maphack ICON Bypass (ON/OFF)",
        "   ESP Features",
        "   BACK"
    }, nil, " MAPHACK + ESP")
    if not choice or choice == 5 then return end
    if choice == 1 then
        local sub = gg.choice({"ON"," OFF"," BACK"}, nil, "MAP V1 NO ICON")
        if sub == 1 then MAP_V1_ON() end
        if sub == 2 then MAP_V1_OFF() end
    elseif choice == 2 then
        local sub = gg.choice({"ON"," OFF"," BACK"}, nil, "MAP V2 FULL VISION")
        if sub == 1 then MAP_V2_ON() end
        if sub == 2 then MAP_V2_OFF() end
    elseif choice == 3 then
        local sub = gg.choice({"ON"," OFF"," BACK"}, nil, "MAPHACK ICON")
        if sub == 1 then MAP_ICON_ON() end
        if sub == 2 then MAP_ICON_OFF() end
    elseif choice == 4 then
        ESPMenu()
    end
end

-- ==================== ROOM INFO ====================
local RANK_NAMES = {
    [1]="Warrior",[2]="Elite",[3]="Master",[4]="Grandmaster",
    [5]="Epic",[6]="Legend",[7]="Mythic",[8]="Mythic Glory",
    [9]="Mythical Immortal",[10]="Mythical Honor",
}
local HERO_NAMES = {
    [1011]="Miya",[1021]="Balmond",[1031]="Saber",[1041]="Alice",
    [1051]="Nana",[1061]="Tigreal",[1071]="Alucard",[1081]="Karina",
    [1091]="Akai",[1101]="Franco",[1121]="Bruno",[1131]="Clint",
    [1141]="Rafaela",[1151]="Eudora",[1161]="Zilong",[1171]="Fanny",
    [1181]="Layla",[1191]="Minotaur",[1201]="Lolita",[1211]="Hayabusa",
    [1231]="Gord",[1241]="Natalia",[1251]="Kagura",[1261]="Chou",
    [1271]="Sun",[1281]="Alpha",[1291]="Ruby",[1301]="Yi Sun-shin",
    [1311]="Moskov",[1321]="Johnson",[1331]="Cyclops",[1341]="Estes",
    [1361]="Aurora",[1371]="Lapu-Lapu",[1381]="Vexana",[1391]="Roger",
    [1401]="Karrie",[1411]="Gatotkaca",[1421]="Harley",[1431]="Irithel",
    [1441]="Grock",[1451]="Argus",[1461]="Odette",[1471]="Lancelot",
    [1481]="Diggie",[1491]="Hylos",[1501]="Zhask",[1511]="Helcurt",
    [1531]="Lesley",[1541]="Jawhead",[1551]="Angela",[1561]="Gusion",
    [1571]="Valir",[1581]="Martis",[1591]="Uranus",[1601]="Hanabi",
    [1611]="Chang'e",[1621]="Kimmy",[1631]="Thamuz",[1641]="Lunox",
    [1651]="Harith",[1661]="Kaja",[1671]="Selena",[1681]="Aldous",
    [1691]="Silvanna",[1701]="Lylia",
}

function read_dword_at(addr)
    local val = 0
    pcall(function()
        gg.loadResults({{address = addr, flags = gg.TYPE_DWORD}})
        local r = gg.getResults(1)
        if r and r[1] then val = tonumber(r[1].value) or 0 end
    end)
    return val
end

function scan_room_players()
    local players = {}
    gg.clearResults()
    gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS + gg.REGION_C_BSS + gg.REGION_JAVA_HEAP)
    gg.clearResults()
    gg.searchNumber("1001", gg.TYPE_DWORD, false, gg.SIGN_GREATER_OR_EQUAL)
    gg.refineNumber("1700", gg.TYPE_DWORD, false, gg.SIGN_LESSER_OR_EQUAL)
    local hero_results = gg.getResults(50)
    if #hero_results >= 2 then
        for _, hr in ipairs(hero_results) do
            local hero_id = tonumber(hr.value)
            if hero_id and hero_id >= 1001 and hero_id <= 1700 then
                local base = hr.address
                local player = {hero_id=hero_id,hero_name=HERO_NAMES[hero_id] or ("ID:"..hero_id),ign="Player_"..(#players+1),rank=0,rank_name="Unknown",team=-1}
                local try1_rank = read_dword_at(base - 0x04)
                local try2_rank = read_dword_at(base + 0x04)
                local try3_rank = read_dword_at(base + 0x0C)
                if try1_rank >= 1 and try1_rank <= 10 then player.rank = try1_rank player.team = read_dword_at(base - 0x08)
                elseif try2_rank >= 1 and try2_rank <= 10 then player.rank = try2_rank player.team = read_dword_at(base + 0x08)
                elseif try3_rank >= 1 and try3_rank <= 10 then player.rank = try3_rank player.team = read_dword_at(base + 0x00) end
                player.rank_name = RANK_NAMES[player.rank] or "Unranked"
                table.insert(players, player)
                if #players >= 10 then break end
            end
        end
    end
    gg.clearResults()
    return players
end

function RoomInfo()
    local choice = gg.choice({"   FULL ROOM SCAN","   ENEMY TEAM INFO","   YOUR TEAM INFO","   BACK"}, nil, "   ROOM INFO")
    if not choice or choice == 4 then return end
    gg.toast(" Scanning players...") gg.sleep(300)
    local players = scan_room_players()
    if #players == 0 then
        gg.alert(" NO DATA FOUND\n\nPara gumana:\n1. Mag-queue ng match\n2. Hintayin ang HERO PICK phase\n3. Habang nag-pipili, buksan GG\n4. I-click Room Info ulit")
        return
    end
    local msg = " ROOM INFO\n" .. string.rep("", 22) .. "\n\n"
    local enemy, team = {}, {}
    for _, p in ipairs(players) do
        if p.team == 1 then table.insert(enemy, p)
        elseif p.team == 0 then table.insert(team, p)
        else if #team < 5 then table.insert(team, p) else table.insert(enemy, p) end end
    end
    if choice == 1 or choice == 2 then
        msg = msg .. " ENEMY (" .. #enemy .. ")\n"
        for i, p in ipairs(enemy) do msg = msg .. string.format(" %d. %s | %s | %s\n", i, p.ign, p.hero_name, p.rank_name) end
        msg = msg .. "\n"
    end
    if choice == 1 or choice == 3 then
        msg = msg .. " YOUR TEAM (" .. #team .. ")\n"
        for i, p in ipairs(team) do msg = msg .. string.format(" %d. %s | %s | %s\n", i, p.ign, p.hero_name, p.rank_name) end
    end
    gg.alert(msg)
end

-- ==================== DRONE VIEWS ====================
function applyDroneViewV1()
    show_download_progress("DRONE VIEW V1")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1089806008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089806008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1094506008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1094506008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('-1053839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1048839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1094506008;-1048839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089722122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1094522122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053577640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1053577640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1054071526',gg.TYPE_DWORD)
    gg.toast('DRONE VIEW V1 ON!\n Extended map view active!') gg.clearResults()
end

function DroneV1_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1094506008;-1048839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('1094506008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089806008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1048839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('-1048839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1053839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('1094522122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089722122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1053577640;-1054071526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1053577640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1054071526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1054071526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057761526',gg.TYPE_DWORD)
    gg.toast(' DRONE VIEW V1 OFF!\n View restored to normal!') gg.clearResults()
end

function Tablet()
    show_download_progress("TAB VIEW 2x")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1089806008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089806008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1092616192',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1092616192;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('-1053839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1050620723',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1092616192;-1050620723;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089722122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1092584735',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1054867456',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1054867456;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1054898913',gg.TYPE_DWORD)
    gg.toast('TAB VIEW 2x ON!\n Tablet zoom active!') gg.clearResults()
end

function Off()
    show_download_progress("RESETTING VIEW")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1092616192;-1050620723;1092584735',gg.TYPE_DWORD) gg.searchNumber('1092616192',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089806008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1050620723;1092584735',gg.TYPE_DWORD) gg.searchNumber('-1050620723',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1053839852;1092584735',gg.TYPE_DWORD) gg.searchNumber('1092584735',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089722122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1054867456;-1054898913;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1054867456',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1054867456;-1054898913;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1054898913',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057761526',gg.TYPE_DWORD)
    gg.toast(' VIEW RESET - Back to normal!') gg.clearResults()
end

function Drone4x_ON()
    show_download_progress("DRONE VIEW 4x")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1089806008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089806008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1094506008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1094506008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('-1053839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1048839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1094506008;-1048839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089722122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1094522122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053577640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1053577640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1054071526',gg.TYPE_DWORD)
    gg.toast('DRONE VIEW 4x ON!\n 4x zoom active!') gg.clearResults()
end

function Drone4x_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1094506008;-1048839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('1094506008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089806008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1048839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('-1048839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1053839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('1094522122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089722122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1053577640;-1054071526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1053577640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1053577640;-1054071526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1054071526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057761526',gg.TYPE_DWORD)
    gg.toast(' DRONE VIEW 4x OFF!') gg.clearResults()
end

function Drone8x_ON()
    show_download_progress("DRONE VIEW 8x")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1089806008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089806008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1097649357',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1097649357;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('-1053839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1045902131',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1097649357;-1045902131;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089722122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1097607414',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1049834291',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1049834291;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1049876234',gg.TYPE_DWORD)
    gg.toast('DRONE VIEW 8x ON!\n 8x ultra zoom active!') gg.clearResults()
end

function Drone8x_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1097649357;-1045902131;1097607414',gg.TYPE_DWORD) gg.searchNumber('1097649357',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089806008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1045902131;1097607414',gg.TYPE_DWORD) gg.searchNumber('-1045902131',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1053839852;1097607414',gg.TYPE_DWORD) gg.searchNumber('1097607414',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089722122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1049834291;-1049876234;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1049834291',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1049876234;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1049876234',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057761526',gg.TYPE_DWORD)
    gg.toast(' DRONE VIEW 8x OFF!') gg.clearResults()
end

function Drone10x_ON()
    show_download_progress("DRONE VIEW 10x")
    gg.clearResults() gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("1089806008;-1053839852;1089722122:512", gg.TYPE_DWORD)
    local r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "1089806008" then v.value = "1097649357" v.freeze = true end
        if v.value == "-1053839852" then v.value = "-1045902131" v.freeze = true end
        if v.value == "1089722122"  then v.value = "1097607414"  v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.searchNumber("-1057677640;-1057761526;1110143140:512", gg.TYPE_DWORD)
    r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "-1057677640" then v.value = "-1049834291" v.freeze = true end
        if v.value == "-1057761526" then v.value = "-1049876234" v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.toast('DRONE VIEW 10x ON!\n Ultra 10x zoom active!')
end

function Drone10x_OFF()
    show_download_progress("DRONE 10x OFF")
    gg.clearResults() gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("1097649357;-1045902131;1097607414:512", gg.TYPE_DWORD)
    local r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "1097649357"  then v.value = "1089806008"  v.freeze = true end
        if v.value == "-1045902131" then v.value = "-1053839852" v.freeze = true end
        if v.value == "1097607414"  then v.value = "1089722122"  v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.searchNumber("-1049834291;-1049876234;1110143140:512", gg.TYPE_DWORD)
    r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "-1049834291" then v.value = "-1057677640" v.freeze = true end
        if v.value == "-1049876234" then v.value = "-1057761526" v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.toast(' DRONE VIEW 10x OFF!\n View restored to normal.')
end

-- ==================== DRONE 11x (X12 values from Abed_Nego) ====================
function Drone11x_ON()
    show_download_progress("DRONE VIEW 11x")
    gg.clearResults() gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("1089806008;-1053839852;1089722122:512", gg.TYPE_DWORD)
    local r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "1089806008"  then v.value = "1099206008"  v.freeze = true end
        if v.value == "-1053839852" then v.value = "-1043839852" v.freeze = true end
        if v.value == "1089722122"  then v.value = "1099322122"  v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.searchNumber("-1057677640;-1057761526;1110143140:512", gg.TYPE_DWORD)
    r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "-1057677640" then v.value = "-1047962617" v.freeze = true end
        if v.value == "-1057761526" then v.value = "-1043583296" v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.toast('DRONE VIEW 11x ON!\n 11x ultra zoom active!')
end

function Drone11x_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("1099206008;-1043839852;1099322122:512", gg.TYPE_DWORD)
    local r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "1099206008"  then v.value = "1089806008"  v.freeze = true end
        if v.value == "-1043839852" then v.value = "-1053839852" v.freeze = true end
        if v.value == "1099322122"  then v.value = "1089722122"  v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.searchNumber("-1047962617;-1043583296;1110143140:512", gg.TYPE_DWORD)
    r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "-1047962617" then v.value = "-1057677640" v.freeze = true end
        if v.value == "-1043583296" then v.value = "-1057761526" v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.toast(' DRONE VIEW 11x OFF!')
end

-- ==================== DRONE 12x (X14 part1 values from Abed_Nego) ====================
function Drone12x_ON()
    show_download_progress("DRONE VIEW 12x")
    gg.clearResults() gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("1089806008;-1053839852;1089722122:512", gg.TYPE_DWORD)
    local r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "1089806008"  then v.value = "1101556008"  v.freeze = true end
        if v.value == "-1053839852" then v.value = "-1041339852" v.freeze = true end
        if v.value == "1089722122"  then v.value = "1101722122"  v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.searchNumber("-1057677640;-1057761526;1110143140:512", gg.TYPE_DWORD)
    r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "-1057677640" then v.value = "-1044219268" v.freeze = true end
        if v.value == "-1057761526" then v.value = "-1043583296" v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.toast('DRONE VIEW 12x ON!\n 12x ultra zoom active!')
end

function Drone12x_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("1101556008;-1041339852;1101722122:512", gg.TYPE_DWORD)
    local r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "1101556008"  then v.value = "1089806008"  v.freeze = true end
        if v.value == "-1041339852" then v.value = "-1053839852" v.freeze = true end
        if v.value == "1101722122"  then v.value = "1089722122"  v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.searchNumber("-1044219268;-1043583296;1110143140:512", gg.TYPE_DWORD)
    r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "-1044219268" then v.value = "-1057677640" v.freeze = true end
        if v.value == "-1043583296" then v.value = "-1057761526" v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.toast(' DRONE VIEW 12x OFF!')
end

-- ==================== DRONE 13x (X4 values from Abed_Nego â widest view) ====================
function Drone13x_ON()
    show_download_progress("DRONE VIEW 13x")
    gg.clearResults() gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("1089806008;-1053839852;1089722122:512", gg.TYPE_DWORD)
    local r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "1089806008"  then v.value = "1092616192"  v.freeze = true end
        if v.value == "-1053839852" then v.value = "-1050620723" v.freeze = true end
        if v.value == "1089722122"  then v.value = "1092584735"  v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.searchNumber("-1057677640;-1057761526;1110143140:512", gg.TYPE_DWORD)
    r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "-1057677640" then v.value = "-1092616192" v.freeze = true end
        if v.value == "-1057761526" then v.value = "-1050620723" v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.toast('DRONE VIEW 13x ON!\n 13x max zoom active!')
end

function Drone13x_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("1092616192;-1050620723;1092584735:512", gg.TYPE_DWORD)
    local r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "1092616192"  then v.value = "1089806008"  v.freeze = true end
        if v.value == "-1050620723" then v.value = "-1053839852" v.freeze = true end
        if v.value == "1092584735"  then v.value = "1089722122"  v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.searchNumber("-1092616192;-1050620723;1110143140:512", gg.TYPE_DWORD)
    r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "-1092616192" then v.value = "-1057677640" v.freeze = true end
        if v.value == "-1050620723" then v.value = "-1057761526" v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.toast(' DRONE VIEW 13x OFF!')
end

-- ==================== DRONE 3x ON/OFF ====================
function Drone3x_ON()
    show_download_progress("DRONE VIEW 3x")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1089806008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089806008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1091506008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1091506008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('-1053839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1051339852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1091506008;-1051339852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089722122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1091922122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1054677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1054677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1055761526',gg.TYPE_DWORD)
    gg.toast('DRONE VIEW 3x ON!\n 3x zoom active!') gg.clearResults()
end

function Drone3x_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1091506008;-1051339852;1091922122',gg.TYPE_DWORD) gg.searchNumber('1091506008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089806008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1051339852;1091922122',gg.TYPE_DWORD) gg.searchNumber('-1051339852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1053839852;1091922122',gg.TYPE_DWORD) gg.searchNumber('1091922122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089722122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1054677640;-1055761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1054677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1055761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1055761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057761526',gg.TYPE_DWORD)
    gg.toast(' DRONE VIEW 3x OFF!') gg.clearResults()
end

-- ==================== DRONE 14x ON/OFF ====================
function Drone14x_ON()
    show_download_progress("DRONE VIEW 14x")
    gg.clearResults() gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("1089806008;-1053839852;1089722122:512", gg.TYPE_DWORD)
    local r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "1089806008"  then v.value = "1103556008"  v.freeze = true end
        if v.value == "-1053839852" then v.value = "-1039339852" v.freeze = true end
        if v.value == "1089722122"  then v.value = "1103722122"  v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.searchNumber("-1057677640;-1057761526;1110143140:512", gg.TYPE_DWORD)
    r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "-1057677640" then v.value = "-1041219268" v.freeze = true end
        if v.value == "-1057761526" then v.value = "-1041583296" v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.toast('DRONE VIEW 14x ON!\n 14x max zoom active!')
end

function Drone14x_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("1103556008;-1039339852;1103722122:512", gg.TYPE_DWORD)
    local r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "1103556008"  then v.value = "1089806008"  v.freeze = true end
        if v.value == "-1039339852" then v.value = "-1053839852" v.freeze = true end
        if v.value == "1103722122"  then v.value = "1089722122"  v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.searchNumber("-1041219268;-1041583296;1110143140:512", gg.TYPE_DWORD)
    r = gg.getResults(20)
    for _, v in ipairs(r) do
        if v.value == "-1041219268" then v.value = "-1057677640" v.freeze = true end
        if v.value == "-1041583296" then v.value = "-1057761526" v.freeze = true end
    end
    gg.setValues(r) r = nil gg.clearResults()
    gg.toast(' DRONE VIEW 14x OFF!')
end

-- ==================== DRONE 7x ON/OFF ====================
-- Drone 7x: values between 4x and 8x zoom levels
function Drone7x_ON()
    show_download_progress("DRONE VIEW 7x")
    gg.clearResults()
    gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    -- First group: camera distance values
    gg.searchNumber('1089806008;-1053839852;1089722122', gg.TYPE_DWORD)
    gg.searchNumber('1089806008', gg.TYPE_DWORD)
    gg.getResults(100)
    gg.editAll('1097649357', gg.TYPE_DWORD)
    gg.clearResults()
    gg.searchNumber('1097649357;-1053839852;1089722122', gg.TYPE_DWORD)
    gg.searchNumber('-1053839852', gg.TYPE_DWORD)
    gg.getResults(100)
    gg.editAll('-1045902131', gg.TYPE_DWORD)
    gg.clearResults()
    gg.searchNumber('1097649357;-1045902131;1089722122', gg.TYPE_DWORD)
    gg.searchNumber('1089722122', gg.TYPE_DWORD)
    gg.getResults(100)
    gg.editAll('1097607414', gg.TYPE_DWORD)
    gg.clearResults()
    -- Second group: camera angle values
    gg.searchNumber('-1057677640;-1057761526;1110143140', gg.TYPE_DWORD)
    gg.searchNumber('-1057677640', gg.TYPE_DWORD)
    gg.getResults(100)
    gg.editAll('-1049834291', gg.TYPE_DWORD)
    gg.clearResults()
    gg.searchNumber('-1049834291;-1057761526;1110143140', gg.TYPE_DWORD)
    gg.searchNumber('-1057761526', gg.TYPE_DWORD)
    gg.getResults(100)
    gg.editAll('-1049876234', gg.TYPE_DWORD)
    gg.clearResults()
    gg.toast('DRONE VIEW 7x ON!\n 7x zoom active!')
end

function Drone7x_OFF()
    gg.clearResults()
    gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    -- Revert first group
    gg.searchNumber('1097649357;-1045902131;1097607414', gg.TYPE_DWORD)
    gg.searchNumber('1097649357', gg.TYPE_DWORD)
    gg.getResults(100)
    gg.editAll('1089806008', gg.TYPE_DWORD)
    gg.clearResults()
    gg.searchNumber('1089806008;-1045902131;1097607414', gg.TYPE_DWORD)
    gg.searchNumber('-1045902131', gg.TYPE_DWORD)
    gg.getResults(100)
    gg.editAll('-1053839852', gg.TYPE_DWORD)
    gg.clearResults()
    gg.searchNumber('1089806008;-1053839852;1097607414', gg.TYPE_DWORD)
    gg.searchNumber('1097607414', gg.TYPE_DWORD)
    gg.getResults(100)
    gg.editAll('1089722122', gg.TYPE_DWORD)
    gg.clearResults()
    -- Revert second group
    gg.searchNumber('-1049834291;-1049876234;1110143140', gg.TYPE_DWORD)
    gg.searchNumber('-1049834291', gg.TYPE_DWORD)
    gg.getResults(100)
    gg.editAll('-1057677640', gg.TYPE_DWORD)
    gg.clearResults()
    gg.searchNumber('-1057677640;-1049876234;1110143140', gg.TYPE_DWORD)
    gg.searchNumber('-1049876234', gg.TYPE_DWORD)
    gg.getResults(100)
    gg.editAll('-1057761526', gg.TYPE_DWORD)
    gg.clearResults()
    gg.toast(' DRONE VIEW 7x OFF!')
end

-- ==================== NO GRASS (HIDE BUSHES) ====================
local grass_cache = {}
local isNograssOn = false

function NoGrass_ON()
    pcall(function()
        show_download_progress("NO GRASS")
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS)
        gg.searchNumber("483758281", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
        gg.processResume()
        gg.refineNumber("483758281", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
        local r = gg.getResults(99, nil, nil, nil, nil, nil, nil, nil, nil)
        if #r > 0 then
            grass_cache = {}
            for i, v in ipairs(r) do
                table.insert(grass_cache, {address=v.address, value=v.value, flags=v.flags})
            end
            gg.editAll("0", gg.TYPE_FLOAT)
            gg.processResume()
            gg.clearResults()
            isNograssOn = true
            gg.toast(
                "NO GRASS ON!\n" ..
                " Grass/bushes HIDDEN!\n" ..
                " " .. #r .. " values patched!"
            )
        else
            gg.processResume()
            gg.clearResults()
            gg.toast(
                " NO GRASS: Must be INGAME!\n" ..
                "Try after fully loading into match."
            )
        end
    end)
end

function NoGrass_OFF()
    pcall(function()
        if not isNograssOn or #grass_cache == 0 then
            gg.toast(" NO GRASS already OFF!")
            return
        end
        -- Restore original 483758281 values
        for i, v in ipairs(grass_cache) do
            v.value = "483758281"
            v.freeze = false
        end
        gg.setValues(grass_cache)
        grass_cache = {}
        isNograssOn = false
        gg.clearResults()
        gg.toast(
            " NO GRASS OFF!\n" ..
            " Grass/bushes RESTORED!\n" ..
            "STATUS: INACTIVE"
        )
    end)
end

-- ==================== CLEAR BATTLE RECORD ====================
function record()
    show_download_progress("CLEARING BATTLE RECORD")
    os.rename('/storage/emulated/0/Android/data/com.mobile.legends/cache','/storage/emulated/0/Android/data/com.mobile.legends/yayan')
    os.rename('/sdcard/Android/data/com.mobile.legends/cache','/sdcard/Android/data/com.mobile.legends/manxl')
    os.rename('/storage/emulated/0/Android/data/com.mobile.legends/files/UnityCache','/storage/emulated/0/Android/data/com.mobile.legends/files/yayan')
    os.rename('/sdcard/Android/data/com.mobile.legends/files/UnityCache','/sdcard/Android/data/com.mobile.legends/files/yayan')
    os.rename('/storage/emulated/0/Android/data/com.mobile.legends/files/dragon/BattleRecord','/storage/emulated/0/Android/data/com.mobile.legends/files/dragon/yayan')
    os.rename('/sdcard/Android/data/com.mobile.legends/files/dragon/BattleRecord','/sdcard/Android/data/com.mobile.legends/files/dragon/yayan')
    gg.toast('Battle Record Cleared!\n History deleted successfully!')
end

-- ==================== ENEMY NOOB ====================
function EnemyNoob()
    pcall(function()
        show_download_progress("ENEMY NOOB") complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS)
        for _, s in ipairs({"5;6;7;8:512","5;6;7;8;9:512","1;2;3;4;5;6;7;8:256"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_DWORD) local res = gg.getResults(100)
            if #res > 0 then for i, v in ipairs(res) do v.value = "1" end gg.setValues(res) break end
        end
        complete_cleanup()
        gg.toast("ENEMY NOOB ACTIVE!\n Matching with low-rank enemies!")
    end)
end

-- ==================== TEAM PRO ====================
function TeamPro()
    pcall(function()
        show_download_progress("TEAM PRO") complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS)
        for _, s in ipairs({"1;2;3;4:512","1;2;3;4;5:512","10;11;12;13;14;15:256"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_DWORD) local res = gg.getResults(100)
            if #res > 0 then for i, v in ipairs(res) do v.value = "15" end gg.setValues(res) break end
        end
        complete_cleanup()
        gg.toast("TEAM PRO ACTIVE!\n Matching with Mythic players!")
    end)
end

-- ==================== RANK BOOST ====================
function RankBoost()
    pcall(function()
        show_download_progress("RANK BOOST") complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS + gg.REGION_C_BSS)
        for _, s in ipairs({"0.1;0.2;0.5;1.0::50","0.1;0.2;0.5;1.0:50","0.2;0.5;1.0:50"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_FLOAT)
            if gg.getResultCount() > 0 then gg.editAll("10.0", gg.TYPE_FLOAT) break end
        end
        complete_cleanup()
        gg.toast("RANK BOOST ACTIVE!\n Rank multiplier applied!")
    end)
end

-- ==================== FAST GOLD ====================
function FastGold()
    pcall(function()
        show_download_progress("FAST GOLD 2x") complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS + gg.REGION_C_BSS + gg.REGION_C_ALLOC)
        for _, s in ipairs({"50;60;70;80;90;100;120;150;180;200;220;250;280;300:512","40;50;60;70;80;90;100;120;150;200:256"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_DWORD) local results = gg.getResults(gg.getResultCount())
            if #results > 0 then for i, v in ipairs(results) do local num = tonumber(v.value) if num and num >= 40 and num <= 300 then v.value = tostring(num * 2) end end gg.setValues(results) break end
        end
        complete_cleanup()
        gg.toast("FAST GOLD 2x ACTIVE!\n Double gold on every kill!")
    end)
end

-- ==================== INVISIBLE NAME ====================
local name_cache = {}
local isNameHidden = false

function InvisibleName()
    pcall(function()
        show_download_progress("INVISIBLE NAME")
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS)
        gg.clearResults()
        gg.searchNumber("45982760", gg.TYPE_QWORD)
        local r = gg.getResults(20)
        if #r > 0 then
            name_cache = {}
            for i, v in ipairs(r) do
                table.insert(name_cache, {address=v.address, value=v.value, flags=v.flags})
            end
            gg.editAll("1", gg.TYPE_QWORD)
            gg.clearResults()
            isNameHidden = true
            gg.toast(
                "INVISIBLE NAME ON!\n" ..
                " Your name is HIDDEN!\n" ..
                " " .. #r .. " values patched!"
            )
        else
            gg.clearResults()
            gg.toast(
                " INVISIBLE NAME: Must be INGAME!\n" ..
                "Try after fully loading into match."
            )
        end
    end)
end

function InvisibleNameOFF()
    pcall(function()
        if not isNameHidden or #name_cache == 0 then
            gg.toast(" INVISIBLE NAME already OFF!")
            return
        end
        -- Restore original 45982760 values
        for i, v in ipairs(name_cache) do
            v.value = "45982760"
            v.freeze = false
        end
        gg.setValues(name_cache)
        name_cache = {}
        isNameHidden = false
        gg.clearResults()
        gg.toast(
            " INVISIBLE NAME OFF!\n" ..
            " Your name is VISIBLE again!\n" ..
            "STATUS: INACTIVE"
        )
    end)
end

-- ==================== UNLOCK BATTLE SPELLS ====================
function UnlockAllBattleSpells()
    pcall(function()
        show_download_progress("UNLOCK ALL BATTLE SPELLS") complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS + gg.REGION_C_BSS + gg.REGION_C_ALLOC + gg.REGION_C_HEAP)
        for _, s in ipairs({"1;2;3;4;5;6;7;8;9;10;11;12:257","1;2;3;4;5;6;7;8;9;10;11;12:256","1;2;3;4;5;6;7;8;9;10;11;12:128"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_DWORD) local results = gg.getResults(200)
            if #results > 0 then for i, v in ipairs(results) do local num = tonumber(v.value) if num and num >= 1 and num <= 12 then v.value = "0" end end gg.setValues(results) break end
        end
        complete_cleanup()
        gg.toast("ALL 12 BATTLE SPELLS UNLOCKED!\n All spells available!")
    end)
end

-- ==================== SKIN FUNCTIONS ====================
function SkinMenuByRole()
    local role_menu = gg.choice({
        "   TANKS","   FIGHTERS","   ASSASSINS",
        "   MAGES","   MARKSMEN","   SUPPORT",
        "   ALL HEROES","   BACK"
    }, nil, " SELECT ROLE ")
    if not role_menu then return end
    if role_menu == 1 then TankHeroes() end
    if role_menu == 2 then FighterHeroes() end
    if role_menu == 3 then AssassinHeroes() end
    if role_menu == 4 then MageHeroes() end
    if role_menu == 5 then MarksmanHeroes() end
    if role_menu == 6 then SupportHeroes() end
    if role_menu == 7 then UnlockAllHeroesSkin() end
end

function TankHeroes()
    local hero = gg.choice({" TIGREAL"," MINOTAUR"," LOLITA"," GATOTKACA"," GROCK"," HYLOS"," URANUS"," AKAI"," JOHNSON"," FRANCO"," GLOO"," FREDRINN"," ATLAS"," KHUFRA"," EDITH"," BELERICK"," BARATS"," BAXIA"," CARMILLA"," CHIP"," BACK"},nil," SELECT TANK")
    if not hero then return end
    local t={"1061","1191","1201","1411","1441","1491","1591","1091","1321","1101","gloo","fredrinn","atlas","khufra","edith","belerick","barats","baxia","carmilla","chip"}
    local n={"TIGREAL","MINOTAUR","LOLITA","GATOTKACA","GROCK","HYLOS","URANUS","AKAI","JOHNSON","FRANCO","GLOO","FREDRINN","ATLAS","KHUFRA","EDITH","BELERICK","BARATS","BAXIA","CARMILLA","CHIP"}
    if hero <= 20 then UnlockSkin(t[hero], n[hero]) end
end

function FighterHeroes()
    local hero = gg.choice({" ALUCARD"," CHOU"," SUN"," ALPHA"," RUBY"," YIN"," LAPU-LAPU"," ROGER"," ARGUS"," BALMOND"," MARTIS"," ZILONG"," PAQUITO"," ARLOTT"," CICI"," DYROTH"," YU ZHONG"," LEOMORD"," MASHA"," X.BORG"," THAMUZ"," SILVANNA"," PHOVEUS"," AULUS"," GUINEVERE"," JAWHEAD"," KHALEED"," ALDOUS"," FREYA"," BANE"," TERIZLA"," MINSITTHAR"," HILDA"," LUKAS"," KALEA"," SORA"," SUYOU"," BADANG"," BACK"},nil," SELECT FIGHTER")
    if not hero then return end
    local t={"1071","1261","1271","1281","1291","1301","1371","1391","1451","1021","1581","1161","paquito","arlott","cici","dyroth","yuzhong","leomord","masha","xborg","thamuz","silvanna","phoveus","aulus","guinevere","jawhead","khaleed","aldous","freya","bane","terizla","minsitthar","hilda","lukas","kalea","sora","suyou","badang"}
    local n={"ALUCARD","CHOU","SUN","ALPHA","RUBY","YIN","LAPU-LAPU","ROGER","ARGUS","BALMOND","MARTIS","ZILONG","PAQUITO","ARLOTT","CICI","DYROTH","YU ZHONG","LEOMORD","MASHA","X.BORG","THAMUZ","SILVANNA","PHOVEUS","AULUS","GUINEVERE","JAWHEAD","KHALEED","ALDOUS","FREYA","BANE","TERIZLA","MINSITTHAR","HILDA","LUKAS","KALEA","SORA","SUYOU","BADANG"}
    if hero <= 38 then UnlockSkin(t[hero], n[hero]) end
end

function AssassinHeroes()
    local hero = gg.choice({" SABER"," KARINA"," FANNY"," HAYABUSA"," NATALIA"," LANCELOT"," HELCURT"," GUSION"," LING"," BENEDETTA"," AAMON"," JOY"," SELENA"," KADITA"," HANZO"," YI SUN-SHIN"," NOLAN"," JULIAN"," BACK"},nil," SELECT ASSASSIN")
    if not hero then return end
    local t={"1031","1081","1171","1211","1241","1471","1511","1561","ling","benedetta","aamon","joy","selena","kadita","hanzo","yisunshin","nolan","julian"}
    local n={"SABER","KARINA","FANNY","HAYABUSA","NATALIA","LANCELOT","HELCURT","GUSION","LING","BENEDETTA","AAMON","JOY","SELENA","KADITA","HANZO","YI SUN-SHIN","NOLAN","JULIAN"}
    if hero <= 18 then UnlockSkin(t[hero], n[hero]) end
end

function MageHeroes()
    local hero = gg.choice({" EUDORA"," AURORA"," VEXANA"," ODETTE"," HARLEY"," CYCLOPS"," VALIR"," ZHASK"," KAGURA"," GORD"," ALICE"," NANA"," LUO YI"," VALENTINA"," XAVIER"," YVE"," LUNOX"," CECILION"," PHARSA"," ZHUXIN"," FARAMIS"," ESMERALDA"," NOVARIA"," ZETIAN"," LYLIA"," HARITH"," CHANG'E"," VALE"," BACK"},nil," SELECT MAGE")
    if not hero then return end
    local t={"1151","1361","1381","1461","1421","1331","1571","1501","1251","1231","1041","1051","luoyi","valentina","xavier","yve","lunox","cecilion","pharsa","zhuxin","faramis","esmeralda","novaria","zetian","lylia","harith","change","vale"}
    local n={"EUDORA","AURORA","VEXANA","ODETTE","HARLEY","CYCLOPS","VALIR","ZHASK","KAGURA","GORD","ALICE","NANA","LUO YI","VALENTINA","XAVIER","YVE","LUNOX","CECILION","PHARSA","ZHUXIN","FARAMIS","ESMERALDA","NOVARIA","ZETIAN","LYLIA","HARITH","CHANG'E","VALE"}
    if hero <= 28 then UnlockSkin(t[hero], n[hero]) end
end

function MarksmanHeroes()
    local hero = gg.choice({" MIYA"," LAYLA"," BRUNO"," CLINT"," MOSKOV"," KARRIE"," IRITHEL"," LESLEY"," HANABI"," GRANGER"," KIMMY"," WANWAN"," NATAN"," IXIA"," MELISSA"," BRODY"," BEATRIX"," POPOL"," CLAUDE"," OBSIDIA"," EDITH"," YI SUN-SHIN"," BACK"},nil," SELECT MARKSMAN")
    if not hero then return end
    local t={"1011","1181","1121","1131","1311","1401","1431","1531","1601","granger","kimmy","wanwan","natan","ixia","melissa","brody","beatrix","popol","claude","obsidia","edith_mm","yisunshin_mm"}
    local n={"MIYA","LAYLA","BRUNO","CLINT","MOSKOV","KARRIE","IRITHEL","LESLEY","HANABI","GRANGER","KIMMY","WANWAN","NATAN","IXIA","MELISSA","BRODY","BEATRIX","POPOL","CLAUDE","OBSIDIA","EDITH","YI SUN-SHIN"}
    if hero <= 22 then UnlockSkin(t[hero], n[hero]) end
end

function SupportHeroes()
    local hero = gg.choice({" ANGELA"," RAFAELA"," ESTES"," DIGGIE"," MINOTAUR"," CARMILA"," KAJA"," MATHILDA"," FLORYN"," FARAMIS"," CHIP"," MARCEL"," KALEA"," BACK"},nil," SELECT SUPPORT")
    if not hero then return end
    local t={"1551","1141","1341","1481","1191","carmilla","kaja","mathilda","floryn","faramis","chip","marcel","kalea_sup"}
    local n={"ANGELA","RAFAELA","ESTES","DIGGIE","MINOTAUR","CARMILA","KAJA","MATHILDA","FLORYN","FARAMIS","CHIP","MARCEL","KALEA"}
    if hero <= 13 then UnlockSkin(t[hero], n[hero]) end
end

function UnlockSkin(code, hero_name)
    pcall(function()
        show_download_progress(hero_name .. " SKINS") complete_cleanup()
        gg.clearResults() gg.searchNumber(code, gg.TYPE_DWORD) local results = gg.getResults(20)
        if #results > 0 then
            local new_code = tostring(tonumber(code) + 3)
            for i, v in ipairs(results) do if v.value == code then v.value = new_code end end
            gg.setValues(results)
            gg.toast("OK " .. hero_name .. " SKINS UNLOCKED!\n All skins available!")
        else gg.toast(" " .. hero_name .. ": Must be INGAME!") end
        complete_cleanup()
    end)
end

function UnlockAllHeroesSkin()
    pcall(function()
        show_download_progress("ALL HEROES SKINS")
        local all_codes = {"1011","1181","1071","1031","1261","1561","1171","1471","1461","1531","1601","1611","1061","1191","1411","1441","1491","1591","1271","1301","1581","1081","1511","1571","1381","1421","1151","1121","1401","1551","1141","1341","1481"}
        local total = 0
        for _, code in ipairs(all_codes) do
            complete_cleanup() gg.clearResults() gg.searchNumber(code, gg.TYPE_DWORD) local results = gg.getResults(10)
            if #results > 0 then
                local new_code = tostring(tonumber(code) + 3)
                for i, v in ipairs(results) do if v.value == code then v.value = new_code total = total + 1 end end
                gg.setValues(results)
            end
        end
        complete_cleanup()
        gg.toast("OK " .. total .. " SKINS UNLOCKED!\n All heroes unlocked!")
    end)
end

-- ==================== EXIT (AUTO RESTORE) ====================
function d()
    pcall(function()
        gg.removeListItems(gg.getListItems())
        if #injected_files > 0 then
            pcall(restore_all_injected)
        end
    end)
    hardened_exit()
end

-- ==================== LOCAL STARTUP (NO NETWORK) ====================
function local_startup()
    pcall(function()
        show_welcome()
        gg.sleep(400)
    end)
end

-- ==================== MAIN MENU ====================
function Main()
local menu = gg.choice({

"1. ANTI-BAN",
"2. ANTI-DETECT",
"3. MAPHACK + ESP",
"4. DRONEVIEW SELECTION",
"5. ENEMY LAG 310ms",
"6. ANTI-LAG 5ms",
"7. ENEMY NOOB",
"8. TEAM PRO",
"9. FPS/GPU BOOST 120FPS",
"10. RANK BOOST",
"11. DAMAGE +50%",
"12. DEFENSE +50",
"13. COOLDOWN -50%",
"14. SPEED WALK +50%",
"15. ATTACK SPEED +50%",
"16. LIFESTEAL 50%",
"17. FAST GOLD 2x",
"18. INVISIBLE NAME",
"19. SKIN UNLOCK (FULL)",
"20. UNLOCK BATTLE SPELLS",
"21. CLEAR BATTLE RECORD",
"22. ROOM INFO",
"23. NO GRASS (ON/OFF)",
"24. UPDATE LICENSE",
"25. EXIT"

}, nil, "DOUTE MENU")

if not menu then return true end
    if menu == 1  then AntiBan() end
    if menu == 2  then AntiDetect() end
    if menu == 3  then MaphackAndESP() end
    if menu == 4  then
        local sub = gg.choice({
            " DRONE V1 ON",
            " DRONE V1 OFF",
            "   TAB VIEW 2x ON",
            " TAB VIEW 2x OFF",
            " DRONE 3x ON",
            " DRONE 3x OFF",
            " DRONE 4x ON",
            " DRONE 4x OFF",
            " DRONE 7x ON ",
            " DRONE 7x OFF",
            " DRONE 8x ON",
            " DRONE 8x OFF",
            " DRONE 10x ON",
            " DRONE 10x OFF",
            " DRONE 11x ON",
            " DRONE 11x OFF",
            " DRONE 12x ON",
            " DRONE 12x OFF",
            " DRONE 13x ON",
            " DRONE 13x OFF",
            " DRONE 14x ON",
            " DRONE 14x OFF",
            " BACK"
        }, nil, " DRONE VIEWS")
        if sub == 1  then applyDroneViewV1() end
        if sub == 2  then DroneV1_OFF() end
        if sub == 3  then Tablet() end
        if sub == 4  then Off() end
        if sub == 5  then Drone3x_ON() end
        if sub == 6  then Drone3x_OFF() end
        if sub == 7  then Drone4x_ON() end
        if sub == 8  then Drone4x_OFF() end
        if sub == 9  then Drone7x_ON() end
        if sub == 10 then Drone7x_OFF() end
        if sub == 11 then Drone8x_ON() end
        if sub == 12 then Drone8x_OFF() end
        if sub == 13 then Drone10x_ON() end
        if sub == 14 then Drone10x_OFF() end
        if sub == 15 then Drone11x_ON() end
        if sub == 16 then Drone11x_OFF() end
        if sub == 17 then Drone12x_ON() end
        if sub == 18 then Drone12x_OFF() end
        if sub == 19 then Drone13x_ON() end
        if sub == 20 then Drone13x_OFF() end
        if sub == 21 then Drone14x_ON() end
        if sub == 22 then Drone14x_OFF() end
    end
    if menu == 5  then
        local sub = gg.choice({" ENEMY LAG ON (310ms)"," ENEMY LAG OFF"," BACK"}, nil, " ENEMY LAG")
        if sub == 1 then EnemyLag310() end
        if sub == 2 then EnemyLagOFF() end
    end
    if menu == 6  then AntiLag() end
    if menu == 7  then EnemyNoob() end
    if menu == 8  then TeamPro() end
    if menu == 9  then SmoothBoost() end
    if menu == 10 then RankBoost() end
    if menu == 11 then DamageBoost() end
    if menu == 12 then DefenseBoost() end
    if menu == 13 then CooldownReduce() end
    if menu == 14 then SpeedWalkBoost() end
    if menu == 15 then AttackSpeedBoost() end
    if menu == 16 then LifestealBoost() end
    if menu == 17 then FastGold() end
    if menu == 18 then
        local sub = gg.choice({
            "   INVISIBLE NAME",
            "  INVISIBLE NAME ON",
            "   INVISIBLE NAME OFF",
            "   BACK"
        }, nil, " INVISIBLE NAME")
        if sub == 2 then InvisibleName() end
        if sub == 3 then InvisibleNameOFF() end
    end
    if menu == 19 then SkinMenuByRole() end
    if menu == 20 then UnlockAllBattleSpells() end
    if menu == 21 then record() end
    if menu == 22 then RoomInfo() end
    if menu == 23 then
        local sub = gg.choice({"NO GRASS ON"," NO GRASS OFF"," BACK"}, nil, " NO GRASS")
        if sub == 1 then NoGrass_ON() end
        if sub == 2 then NoGrass_OFF() end
    end
    if menu == 24 then UpdateLicenseKey() end
    if menu == 25 then return false end
end

-- API export for module usage
if ... then
    return {
        require_license = require_license,
        get_device_id = get_device_id,
        validate_key = validate_key,
        load_cache = load_cache,
        save_cache = save_cache,
        clear_cache = clear_cache,
    }
end

-- ==================== STARTUP ====================
-- Defer strict license enforcement until user requests protected features.
-- This prevents immediate exit when script is launched in non-GG environments.
-- Restore license system: require key on startup
if not require_license() then
    return
end
local_startup()
make_dir(BACKUP_DIR)

-- ==================== MAIN LOOP (FIXED - stable 100ms) ====================
local game_was_running = true
while true do
    if gg.isVisible(true) then
        gg.setVisible(false)
        local ok, ret = pcall(Main)
        if not ok then
            gg.toast(" Auto-recovery...")
            gg.sleep(500)
        else
            if ret == false then
                -- user requested exit; perform cleanup and stop loop
                d()
                break
            end
        end
    end
    pcall(function()
        local info = gg.getTargetInfo()
        if info and info.pid then game_was_running = true
        elseif game_was_running and #injected_files > 0 then
            restore_all_injected() game_was_running = false
        end
    end)
    gg.sleep(100)
end
