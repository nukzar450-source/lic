local LICENSE_URL = 'https://raw.githubusercontent.com/nukzar450-source/lic/main/p.txt'
local DIR = (type(gg) == 'table' and gg.getFile and gg.getFile() or '')
DIR = (DIR:match('(.*/)') or '/sdcard/')
DIR = DIR:gsub('([^/])$','%1')

local function read(f)
    local h = io.open(DIR..f, 'r')
    if h then local s = h:read('*a') h:close() return s end
    return nil
end

local old_read = read
function read(f)
    if f == 'p.txt' and type(_G) == 'table' and type(_G.LOADER_LICENSE_TEXT) == 'string' and #_G.LOADER_LICENSE_TEXT > 0 then
        return _G.LOADER_LICENSE_TEXT
    end
    return old_read(f)
end

local function write(f, s)
    local h = io.open(DIR..f, 'w')
    if h then h:write(s) h:close() return true end
    return false
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
    if line:find('\0') or line:find('[\1-\8\11-\31]') then return nil end
    if #line > 1024 then return nil end
    
    line = line:gsub('\r', ''):gsub('^%s+', ''):gsub('%s+$', '')
    if line == '' or line:match('^#') then return nil end
    local key, expiry, dev = line:match('^([^|]+)|([^|]+)|?(.*)$')
    if not key then return nil end
    
    key = key:gsub('%s+', '')
    expiry = expiry and expiry:gsub('%s+', '') or ''
    dev = dev and dev:gsub('%s+', '') or ''
    
    if #key == 0 or #key > 512 or not key:match('^[A-Za-z0-9\\-]+$') then return nil end
    if #expiry ~= 10 or not expiry:match('^%d%d%d%d%-\\d%d%-\\d%d$') then return nil end
    
    if dev == '' then dev = nil end
    return key, expiry, dev
end

local function expiry_valid(expiry, now)
    if type(expiry) ~= 'string' then return false end
    local y, m, d = expiry:match('(%d%d%d%d)-(%d%d)-(%d%d)')
    if not y then return false end
    now = tonumber(now) or os.time()
    return os.time({year = tonumber(y), month = tonumber(m), day = tonumber(d), hour = 23}) >= now
end

local ID = nil
local function isVirtualEnvironment()
    local checks = {
        function()
            local f = io.open('/proc/cpuinfo', 'r')
            if f then
                local c = f:read('*a') f:close()
                if c:lower():find('qemu') or c:lower():find('goldfish') or c:lower():find('ranchu') then return true end
            end
            return false
        end,
        function()
            local f = io.open('/proc/version', 'r')
            if f then
                local v = f:read('*a') f:close()
                if v:lower():find('generic') or v:lower():find('emulator') then return true end
            end
            return false
        end,
        function()
            local f = io.open('/system/build.prop', 'r')
            if f then
                for line in f:lines() do
                    if line:lower():find('ro.kernel.qemu') or line:lower():find('ro.secure=0') or line:lower():find('vbox') then f:close(); return true end
                end
                f:close()
            end
            return false
        end,
        function()
            local ok, info = pcall(gg.getTargetInfo)
            if ok and info and info.uid then
                local uid = tonumber(info.uid)
                if uid and (uid > 99999 or uid < 10000) then return true end
            end
            return false
        end,
        function()
            local f = io.open('/proc/mounts','r')
            if f then
                local m = f:read('*a') f:close()
                if string.find(m, '/data/media/0') == nil and (string.find(m, 'vmos') or string.find(m, 'vphone')) then return true end
            end
            return false
        end
    }

    for _, check in ipairs(checks) do
        local ok, res = pcall(check)
        if ok and res then return true end
    end
    return false
end

local function generateHardwareHWID()
    local parts = {}
    local info = nil
    local ok, res = pcall(function() return gg.getTargetInfo() end)
    if ok and type(res) == 'table' then info = res end

    table.insert(parts, tostring(info and info.uid or "10100"))
    table.insert(parts, tostring(info and info.x64 and "64" or "32"))
    local w = (info and info.nativeWidth) or 1080
    local h = (info and info.nativeHeight) or 2400
    table.insert(parts, w .. "X" .. h)

    local function read_serial()
        local f = io.open('/system/build.prop','r')
        if not f then return nil end
        for line in f:lines() do
            local v = line:match('^ro%.serialno=(.+)$')
            if v and #v > 0 then f:close(); return v end
        end
        f:close()
        return nil
    end

    local serial = read_serial()
    if serial then table.insert(parts, serial) end

    local rawId = table.concat(parts, '|')
    if type(gg) == 'table' and type(gg.hash) == 'function' then
        local ok2, h = pcall(function() return gg.hash(rawId, 'sha256') end)
        if ok2 and type(h) == 'string' then return string.upper(h:sub(1,16)) end
    end

    local hash = 5381
    for i = 1, #rawId do
        hash = ((hash * 33) + string.byte(rawId, i)) % 4294967296
    end
    return string.upper(string.format("%x", hash)):sub(1,16)
end

do
    local loader_present = type(_G) == 'table' and (_G.LOADER_SCRIPT_VERIFIED ~= nil)
    if not loader_present then
        local candidates = {'p.txt', 'p.txt.txt', 'license.txt', 'local_p.txt'}
        local found = nil
        for _, name in ipairs(candidates) do
            local c = read(name)
            if type(c) == 'string' and #c > 0 then found = c; break end
        end
        if found then
            _G = _G or {}
            _G.LOADER_LOCAL_ONLY = true
            _G.LOADER_LICENSE_TEXT = found
            _G.LOADER_SCRIPT_VERIFIED = true
            local function gen_hwid_local()
                local parts = {}
                local ok, info = pcall(gg.getTargetInfo)
                if ok and info then
                    table.insert(parts, tostring(info.uid or '10100'))
                    table.insert(parts, tostring(info.x64 and '64' or '32'))
                else
                    table.insert(parts, '10100')
                    table.insert(parts, '32')
                end
                local w = (info and info.nativeWidth) or 1080
                local h = (info and info.nativeHeight) or 2400
                table.insert(parts, w .. 'X' .. h)
                local rawId = table.concat(parts, '-')
                local hash = 5381
                for i = 1, #rawId do
                    hash = ((hash * 33) + string.byte(rawId, i)) % 4294967296
                end
                return string.upper(string.format('%x', hash))
            end
            _G.LOADER_HWID = gen_hwid_local()
        end
    end
end

local function start_local_whitelist()
    if type(_G) == 'table' and type(_G.LOADER_SCRIPT_VERIFIED) == 'boolean' and not _G.LOADER_SCRIPT_VERIFIED then
    end
    
    if isVirtualEnvironment() then
        notify_and_exit('Virtual environment detected; aborting')
    end
    if type(_G) == 'table' and type(_G.LOADER_HWID) == 'string' and #_G.LOADER_HWID > 0 then
        if _G.LOADER_HWID:match('^[0-9A-Fa-f]+$') and #_G.LOADER_HWID >= 8 and #_G.LOADER_HWID <= 16 then
            ID = _G.LOADER_HWID
        else
            notify_and_exit('Invalid HWID provided by loader; aborting')
        end
    else
        ID = generateHardwareHWID()
    end
end

local RANKED_SCHEDULED = false
local RUNNING = true

local function hardened_exit()
    pcall(function() if gg and gg.removeListItems then gg.removeListItems(gg.getListItems() or {}) end end)
    pcall(function() if #injected_files > 0 then restore_all_injected() end end)
    collectgarbage()
    notify_and_exit('Exit')
end

local function notify_and_exit(msg)
    pcall(function()
        if type(gg) == 'table' and type(gg.alert) == 'function' then gg.alert(tostring(msg)) end
    end)
    pcall(function() if type(gg) == 'table' and gg.removeListItems then gg.removeListItems(gg.getListItems() or {}) end end)
    pcall(function() if #injected_files > 0 then restore_all_injected() end end)
    collectgarbage()
    if type(os) == 'table' and type(os.exit) == 'function' then os.exit(0) end
end

local function check_key(key, license_text, license_headers)
    if type(key) ~= 'string' or #key == 0 then return false, 'invalid_key' end
    if #key > 512 then return false, 'key_too_long' end
    if key:find('\0') or key:find('[\1-\8\11-\31]') then return false, 'invalid_chars' end
    
    local text = license_text
    local headers = license_headers or {}
    
    if not text then return nil, 'network' end
    
    if type(text) ~= 'string' or #text == 0 then return nil, 'empty_license_list' end
    
    local now = nil
    if type(_G) == 'table' and type(_G.LOADER_SERVER_EPOCH) == 'number' then
        now = _G.LOADER_SERVER_EPOCH
        LICENSE_TIME_SOURCE = 'server'
    else
        local date_header = nil
        if type(headers) == 'table' then date_header = headers.Date or headers.date end
        if date_header and type(date_header) == 'string' and #date_header > 0 then
            now = parse_http_date(tostring(date_header))
            if now then LICENSE_TIME_SOURCE = 'server' end
        end
    end
    if not now then
        if type(_G) == 'table' and _G.LOADER_LOCAL_ONLY then
            now = os.time()
            LICENSE_TIME_SOURCE = 'local'
        else
            return nil, 'no_server_date'
        end
    end

    local function scan_lines()
        for line in text:gmatch('([^\r\n]+)') do
            local k, e, d = parse_line(line)
            if not k or not e then
            else
                if k == key then
                    if not expiry_valid(e, now) then
                        if time_was_fallback then
                            return false, 'expired', e
                        end
                        return false, 'expired', e
                    end
                    if not d then return false, 'no_device', e end
                    if not ID or type(ID) ~= 'string' or #ID == 0 then return false, 'invalid_hwid' end
                    if d == '*' then return true, e end
                    if d == ID then return true, e end
                    return false, 'wrong_device', e
                end
            end
        end
        return false, 'not_found'
    end

    local ok_scan, a, b, c = pcall(scan_lines)
    if not ok_scan then
        local function preview(n)
            local out = {}
            local i = 0
            for line in (text or '') :gmatch('([^\r\n]+)') do
                i = i + 1
                if i > n then break end
                table.insert(out, line)
            end
            return table.concat(out, '\n')
        end
        notify_and_exit('Failed reading license lines: ' .. tostring(a) .. '\nPreview:\n' .. preview(8))
    end
    return a, b, c
end

function get_device_id()
    return ID
end

function require_license()
    local hwid = (type(_G) == 'table' and _G.LOADER_HWID) or nil
    local license_text = (type(_G) == 'table' and _G.LOADER_LICENSE_TEXT) or nil
    if type(license_text) ~= 'string' or #license_text == 0 then
        if type(gg) == 'table' and type(gg.alert) == 'function' then
            gg.alert("Ошибка: Лицензия не найдена или пуста!")
        else
            print("Ошибка: Лицензия не найдена или пуста!")
        end
        return false
    end
    if not hwid then
        notify_and_exit('Loader communication failure: hwid missing')
        return false
    end
    local authorized = false
    for line in license_text:gmatch('[^\r\n]+') do
        if line:upper():find(hwid:upper(), 1, true) then authorized = true break end
    end
    if not authorized then
        notify_and_exit('Access denied for device: ' .. tostring(hwid))
        return false
    end
    return true
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

function show_download_progress(name)
    name = tostring(name or "...")
    local steps = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
    gg.sleep(150)
    for _, pct in ipairs(steps) do
        local filled = math.floor(pct / 10)
        local bar = string.rep("=", filled) .. string.rep(" ", 10 - filled)
        gg.sleep(120)
    end
    gg.sleep(100)
    gg.sleep(400)
end

local OFFSETS = {
    ["0"] = "0x7",
    ["0.0"] = "0x7",
    ["00"] = "0x7",
    ["01"] = "0x6",
    ["0.25"] = "0x2caae",
    ["03"] = "0x2d8",
    ["04"] = "0x44",
    ["0.5"] = "0x48d",
    ["0.50"] = "0x48d",
    ["08"] = "0x70",
    ["09"] = "0x74a2",
    ["1"] = "0x6",
    ["10"] = "0x74a9",
    ["100"] = "0x3008",
    ["1000"] = "0x9218",
    ["100000"] = "0x23f10",
    ["1001"] = "0x7d28",
    ["101"] = "0x8ec8",
    ["1011"] = "0x9448",
    ["1021"] = "0x9594",
    ["1031"] = "0x9b38",
    ["1041"] = "0x9ddc",
    ["1051"] = "0x9728",
    ["1061"] = "0x7d64",
    ["1071"] = "0x91cc",
    ["1081"] = "0x7d70",
    ["11"] = "0xa160",
    ["1131"] = "0x3ad8",
    ["1141"] = "0x13879",
    ["1161"] = "0x14059",
    ["1171"] = "0x41cab",
    ["1181"] = "0x14ad9",
    ["12"] = "0x1bf8",
    ["120"] = "0x3cb0",
    ["1201"] = "0x15379",
    ["128"] = "0x13e8",
    ["1281"] = "0x177d9",
    ["13"] = "0x1688",
    ["130"] = "0x7155",
    ["1311"] = "0x3fc1",
    ["1321"] = "0x1a38",
    ["1331"] = "0x18ba1",
    ["1371"] = "0x18d99",
    ["1391"] = "0x6280",
    ["14"] = "0xa2c8",
    ["1411"] = "0xfa0",
    ["1421"] = "0x18e41",
    ["1481"] = "0x5dd91",
    ["15"] = "0x2678",
    ["150"] = "0x79d4",
    ["1500"] = "0x13fe1",
    ["1501"] = "0x17b0",
    ["1511"] = "0x15c01",
    ["1531"] = "0x1081",
    ["1541"] = "0xea1",
    ["1551"] = "0x18fc9",
    ["16"] = "0x328",
    ["1621"] = "0x4480",
    ["1681"] = "0x446ab",
    ["17"] = "0x6d4",
    ["18"] = "0x111",
    ["180"] = "0x1358",
    ["19"] = "0x5a38",
    ["2"] = "0x120",
    ["20"] = "0x2d4",
    ["200"] = "0x7a08",
    ["21"] = "0x24c",
    ["22"] = "0x8e20",
    ["220"] = "0x2ee8",
    ["23"] = "0xabd0",
    ["24"] = "0x998",
    ["240"] = "0x9e0c",
    ["25"] = "0x2de0",
    ["250"] = "0x7a48",
    ["255"] = "0xaa60",
    ["256"] = "0x13",
    ["257"] = "0x5",
    ["260"] = "0x7288",
    ["28"] = "0x1b1",
    ["280"] = "0x4700",
    ["3"] = "0x2d8",
    ["30"] = "0x75aa",
    ["300"] = "0x9418",
    ["310"] = "0x9db8",
    ["32"] = "0x2f3",
    ["34"] = "0xbd8",
    ["35"] = "0x7928",
    ["36"] = "0xb48",
    ["38"] = "0x5840",
    ["39"] = "0xa260",
    ["4"] = "0x44",
    ["40"] = "0x12f8",
    ["400"] = "0x9d60",
    ["41"] = "0xa318",
    ["42"] = "0x9638",
    ["43"] = "0x90e0",
    ["45"] = "0x92c0",
    ["47"] = "0x9390",
    ["48"] = "0x1e08",
    ["49"] = "0x9ce8",
    ["5"] = "0x2a",
    ["50"] = "0xaf00",
    ["500"] = "0x4a30",
    ["512"] = "0x11f",
    ["54"] = "0x94c4",
    ["55"] = "0xab98",
    ["6"] = "0x40",
    ["60"] = "0x9c8",
    ["600"] = "0xf61",
    ["64"] = "0x20",
    ["65"] = "0x937c",
    ["65536"] = "0x76",
    ["7"] = "0x9e94",
    ["70"] = "0x7174",
    ["75"] = "0x8f5c",
    ["79"] = "0x9538",
    ["8"] = "0x70",
    ["80"] = "0x11d8",
    ["81"] = "0xaa54",
    ["89"] = "0xa3e0",
    ["9"] = "0x74a2",
    ["90"] = "0x7990",
    ["91"] = "0x5380",
    ["99"] = "0x253",
}
local OFFSETS_INFO = { loaded = true, count = 249, version = 0 }

function get_mapped_addr(val)
    if type(val) ~= 'string' then return nil end
    local hex = OFFSETS[val]
    if not hex then return nil end
    if type(hex) == 'number' then return hex end
    if type(hex) == 'string' then
        if hex:match('^0x') then
            return tonumber(hex:sub(3), 16)
        else
            return tonumber(hex)
        end
    end
    return nil
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
    for _, fname in ipairs(injected_files) do restore_file(fname) end
    injected_files = {}
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

function show_welcome()
    local offsets_status = "DISABLED (using search)"
    if OFFSETS_INFO.loaded then
        offsets_status = "ENABLED (" .. OFFSETS_INFO.count .. " offsets)"
    end
    
    local version_note = ""
    if OFFSETS_INFO.version > 0 then
        version_note = "\nOffsets updated: " .. os.date("%Y-%m-%d", OFFSETS_INFO.version)
    elseif OFFSETS_INFO.loaded then
        version_note = "\nEmbedded offsets are active"
    else
        version_note = "\nNo offsets available"
    end
    
    gg.alert([[
===== MOD MENU =====

Welcome to the script.

Offsets: ]] .. offsets_status .. version_note .. [[

Use the menu to apply game modifications.
]])
end


function DamageBoost()
    return
end

function CooldownReduce()
    return
end

function AntiLag()
    return
end

function EnemyLag310()
    pcall(function()
        show_download_progress("ENEMY LAG 310ms")
        gg.clearResults()
        local total_applied = 0
        gg.setRanges(gg.REGION_C_ALLOC + gg.REGION_ANONYMOUS)
        local ping_patterns = {
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
        else
        end
    end)
end

function EnemyLagOFF()
    pcall(function()
        gg.removeListItems(gg.getListItems())
        gg.clearResults()
    end)
end

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
    end)
end


local function deepClean()
    return
end

function AntiBan()
    return
end

function AntiDetect()
    return
end

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
    else
        gg.clearResults()
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
    else
        gg.clearResults()
    end
end

function MAP_V2_ON()
    show_download_progress("MAPHACK V2")
    gg.clearResults()
    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("98784247822;47244640279", gg.TYPE_QWORD)
    gg.searchNumber("98784247822", gg.TYPE_QWORD)
    local r = gg.getResults(100)
    if #r > 0 then
        gg.editAll("98784247823", gg.TYPE_QWORD)
        gg.clearResults()
        deepClean()
        gg.sleep(600)
    else
        gg.clearResults()
    end
end

function MAP_V2_OFF()
    gg.clearResults()
    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("98784247823", gg.TYPE_QWORD)
    local r = gg.getResults(100)
    if #r > 0 then
        gg.editAll("98784247822", gg.TYPE_QWORD)
        gg.clearResults()
    else
        gg.clearResults()
    end
    gg.removeListItems(gg.getListItems())
end

function ESPMenu()
    return
end

function VisibleCheck()
    return
end

function LineESP()
    return
end

function BoxESP()
    return
end

function NameESP()
    return
end

function DistanceESP()
    return
end

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
            return
        end
        local pkg = info.packageName
        local stx = nil
        local label = ""
        if pkg == "com.mobile.legends" then
            stx = {
            }
            label = "ORI"
        elseif pkg == "com.mobile.legends.usa" then
            stx = {
            }
            label = "US"
        else
            return
        end

        gg.sleep(300)

        map_icon_MOV = findBypassAddr("-2.74878956e11")
        if not map_icon_MOV then
            return
        end

        map_icon_RET = findBypassAddr("-6.13017998e13")
        if not map_icon_RET then
            return
        end

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
            scrambleMemory()
            gg.sleep(600)
        else
        end
    end)
end

function MAP_ICON_OFF()
    pcall(function()
        local confirm = gg.choice({
        }, nil, " MAP ICON OFF")
        if confirm == 1 then
            map_icon_patched = false
            map_icon_MOV = nil
            map_icon_RET = nil
            gg.sleep(500)
            pcall(function()
                local info = gg.getTargetInfo()
                if info and info.pid then
                    os.execute("kill -9 " .. info.pid .. " 2>/dev/null")
                end
            end)
        else
        end
    end)
end



function MaphackAndESP()
        local choice = gg.choice({
        }, nil, " MAPHACK")
    if not choice or choice == 3 then return end
        if choice == 1 then
        local sub = gg.choice({"ON","OFF","BACK"}, nil, "MAP V1")
        if sub == 1 then MAP_V1_ON() end
        if sub == 2 then MAP_V1_OFF() end
    elseif choice == 2 then
        local sub = gg.choice({"ON","OFF","BACK"}, nil, "MAP V2")
        if sub == 1 then MAP_V2_ON() end
        if sub == 2 then MAP_V2_OFF() end
        elseif choice == 3 then
            local sub = gg.choice({"ON","OFF","BACK"}, nil, "MAP ICON")
            if sub == 1 then MAP_ICON_ON() end
            if sub == 2 then MAP_ICON_OFF() end
    end
end

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

function applyDroneViewV1()
    show_download_progress("DRONE VIEW V1")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1089806008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089806008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1094506008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1094506008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('-1053839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1048839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1094506008;-1048839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089722122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1094522122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053577640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1053577640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1054071526',gg.TYPE_DWORD)
end

function DroneV1_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1094506008;-1048839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('1094506008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089806008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1048839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('-1048839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1053839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('1094522122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089722122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1053577640;-1054071526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1053577640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1054071526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1054071526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057761526',gg.TYPE_DWORD)
end

function Tablet()
    show_download_progress("TAB VIEW 2x")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1089806008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089806008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1092616192',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1092616192;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('-1053839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1050620723',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1092616192;-1050620723;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089722122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1092584735',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1054867456',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1054867456;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1054898913',gg.TYPE_DWORD)
end

function Off()
    show_download_progress("RESETTING VIEW")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1092616192;-1050620723;1092584735',gg.TYPE_DWORD) gg.searchNumber('1092616192',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089806008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1050620723;1092584735',gg.TYPE_DWORD) gg.searchNumber('-1050620723',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1053839852;1092584735',gg.TYPE_DWORD) gg.searchNumber('1092584735',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089722122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1054867456;-1054898913;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1054867456',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1054867456;-1054898913;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1054898913',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057761526',gg.TYPE_DWORD)
end

function Drone4x_ON()
    show_download_progress("DRONE VIEW 4x")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1089806008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089806008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1094506008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1094506008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('-1053839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1048839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1094506008;-1048839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089722122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1094522122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053577640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1053577640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1054071526',gg.TYPE_DWORD)
end

function Drone4x_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1094506008;-1048839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('1094506008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089806008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1048839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('-1048839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1053839852;1094522122',gg.TYPE_DWORD) gg.searchNumber('1094522122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089722122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1053577640;-1054071526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1053577640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1053577640;-1054071526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1054071526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057761526',gg.TYPE_DWORD)
end

function Drone8x_ON()
    show_download_progress("DRONE VIEW 8x")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1089806008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089806008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1097649357',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1097649357;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('-1053839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1045902131',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1097649357;-1045902131;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089722122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1097607414',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1049834291',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1049834291;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1049876234',gg.TYPE_DWORD)
end

function Drone8x_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1097649357;-1045902131;1097607414',gg.TYPE_DWORD) gg.searchNumber('1097649357',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089806008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1045902131;1097607414',gg.TYPE_DWORD) gg.searchNumber('-1045902131',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1053839852;1097607414',gg.TYPE_DWORD) gg.searchNumber('1097607414',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089722122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1049834291;-1049876234;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1049834291',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1049876234;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1049876234',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057761526',gg.TYPE_DWORD)
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
end

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
end

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
end

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
end

function Drone3x_ON()
    show_download_progress("DRONE VIEW 3x")
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1089806008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089806008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1091506008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1091506008;-1053839852;1089722122',gg.TYPE_DWORD) gg.searchNumber('-1053839852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1051339852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1091506008;-1051339852;1089722122',gg.TYPE_DWORD) gg.searchNumber('1089722122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1091922122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1054677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1054677640;-1057761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1057761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1055761526',gg.TYPE_DWORD)
end

function Drone3x_OFF()
    gg.clearResults() gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
    gg.searchNumber('1091506008;-1051339852;1091922122',gg.TYPE_DWORD) gg.searchNumber('1091506008',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089806008',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1051339852;1091922122',gg.TYPE_DWORD) gg.searchNumber('-1051339852',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1053839852',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('1089806008;-1053839852;1091922122',gg.TYPE_DWORD) gg.searchNumber('1091922122',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('1089722122',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1054677640;-1055761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1054677640',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057677640',gg.TYPE_DWORD) gg.clearResults()
    gg.searchNumber('-1057677640;-1055761526;1110143140',gg.TYPE_DWORD) gg.searchNumber('-1055761526',gg.TYPE_DWORD) gg.getResults(100) gg.editAll('-1057761526',gg.TYPE_DWORD)
end

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
end

function Drone7x_ON()
    show_download_progress("DRONE VIEW 7x")
    gg.clearResults()
    gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
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
end

function Drone7x_OFF()
    gg.clearResults()
    gg.setRanges(gg.REGION_C_BSS + gg.REGION_ANONYMOUS)
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
end

local grass_cache = {}
local isNograssOn = false

function NoGrass_ON()
    return
end

function NoGrass_OFF()
    return
end

function record()
    show_download_progress("CLEARING BATTLE RECORD")
    os.rename('/storage/emulated/0/Android/data/com.mobile.legends/cache','/storage/emulated/0/Android/data/com.mobile.legends/yayan')
    os.rename('/sdcard/Android/data/com.mobile.legends/cache','/sdcard/Android/data/com.mobile.legends/manxl')
    os.rename('/storage/emulated/0/Android/data/com.mobile.legends/files/UnityCache','/storage/emulated/0/Android/data/com.mobile.legends/files/yayan')
    os.rename('/sdcard/Android/data/com.mobile.legends/files/UnityCache','/sdcard/Android/data/com.mobile.legends/files/yayan')
    os.rename('/storage/emulated/0/Android/data/com.mobile.legends/files/dragon/BattleRecord','/storage/emulated/0/Android/data/com.mobile.legends/files/dragon/yayan')
    os.rename('/sdcard/Android/data/com.mobile.legends/files/dragon/BattleRecord','/sdcard/Android/data/com.mobile.legends/files/dragon/yayan')
end

function EnemyNoob()
    pcall(function()
        show_download_progress("ENEMY NOOB") complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS)
        for _, s in ipairs({"5;6;7;8:512","5;6;7;8;9:512","1;2;3;4;5;6;7;8:256"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_DWORD) local res = gg.getResults(100)
            if #res > 0 then for i, v in ipairs(res) do v.value = "1" end gg.setValues(res) break end
        end
        complete_cleanup()
    end)
end

function TeamPro()
    pcall(function()
        show_download_progress("TEAM PRO") complete_cleanup()
        gg.setRanges(gg.REGION_ANONYMOUS)
        for _, s in ipairs({"1;2;3;4:512","1;2;3;4;5:512","10;11;12;13;14;15:256"}) do
            gg.clearResults() gg.searchNumber(s, gg.TYPE_DWORD) local res = gg.getResults(100)
            if #res > 0 then for i, v in ipairs(res) do v.value = "15" end gg.setValues(res) break end
        end
        complete_cleanup()
    end)
end

function RankBoost()
    return
end

function InvisibleName()
    return
end

function InvisibleNameOFF()
    return
end

function UnlockAllBattleSpells()
    return
end

function SkinMenuByRole()
    local role_menu = gg.choice({
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
    return
end

function UnlockAllHeroesSkin()
    return
end

function d()
    pcall(function() gg.removeListItems(gg.getListItems()) end)
    if #injected_files > 0 then
        restore_all_injected()
        gg.sleep(300)
    end
    notify_and_exit('Exit')
end

function local_startup()
    hardened_exit()
end

function Main()
local menu = gg.choice({

"RANKED (schedule for Lobby)",

}, nil, "DOUTE MENU")

if not menu then return end
    if menu == 1 then MaphackAndESP() end
    if menu == 2 then
        local sub = gg.choice({
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
    if menu == 3 then
        local sub = gg.choice({" ENEMY LAG ON (310ms)"," ENEMY LAG OFF"," BACK"}, nil, " ENEMY LAG")
        if sub == 1 then EnemyLag310() end
        if sub == 2 then EnemyLagOFF() end
    end
    if menu == 4 then AntiLag() end
    if menu == 5 then
        RANKED_SCHEDULED = true
        return
    end
    if menu == 6 then SmoothBoost() end
    if menu == 7 then record() end
    if menu == 8 then RoomInfo() end
    if menu == 9 then UpdateLicenseKey() end
    if menu == 10 then d() end
end

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

local _SCRIPT_ALREADY_STARTED = false

local function startup_verifications()
    if not (type(_G) == 'table' and _G.LOADER_AUTHORIZED) then
        if type(os) == 'table' and type(os.exit) == 'function' then os.exit() end
        return false
    end

    if type(_G) == 'table' and _G.LOADER_HWID and _G.LOADER_HWID ~= "ТВОЙ_HWID_КАПСОМ" then
    end

    return true
end

local function remove_sensitive_files()
    return
end

local _ok_start, _err_start = pcall(function()
    if not (type(_G) == 'table' and _G.LOADER_AUTHORIZED == true) then
        notify_and_exit('Device not authorized by loader')
    end
    
    
    remove_sensitive_files()
end)
if not _ok_start then
    notify_and_exit('Startup error')
end
make_dir(BACKUP_DIR)

if not require_license() then
    return
end

local function freeze_critical_state()
    if type(_G) == 'table' then
        _G.LOADER_HWID = nil
        _G.LOADER_LICENSE_TEXT = nil
        _G.LOADER_LICENSE_HEADERS = nil
        _G.LOADER_SCRIPT_VERIFIED = nil
        _G.LOADER_SCRIPT_HASH = nil
    end
end

freeze_critical_state()

local game_was_running = true
while RUNNING do
    if gg.isVisible(true) then
        gg.setVisible(false)
        local ok, err = pcall(Main)
        if not ok then
            if tostring(err) == "__FORCED_EXIT__" then
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
    pcall(function()
        if RANKED_SCHEDULED then
            local players = scan_room_players()
            if type(players) == 'table' and #players == 0 then
                EnemyNoob()
                gg.sleep(150)
                TeamPro()
                gg.sleep(150)
                RankBoost()
                RANKED_SCHEDULED = false
            end
        end
    end)
    gg.sleep(100)
end

hardened_exit()

