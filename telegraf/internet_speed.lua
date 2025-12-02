#!/usr/bin/env luajit

-- Lightweight speed test using curl, written in LuaJIT.
-- Outputs: internet_speed,host=<host> download_mbps=...,upload_mbps=...

local HOST = (io.popen("hostname", "r"):read("*l")) or "unknown"

local DOWNLOAD_URLS = {
	"https://speed.hetzner.de/10MB.bin",
	"https://speed.cloudflare.com/__down?bytes=10000000",
	"http://ipv4.download.thinkbroadband.com/10MB.zip",
}

local UPLOAD_URL = "https://speed.cloudflare.com/__up"
local UPLOAD_SIZE = 512 * 1024 -- bytes

local function run_cmd(cmd)
	local f = io.popen(cmd, "r")
	if not f then
		return ""
	end
	local out = f:read("*a") or ""
	f:close()
	return out
end

-- Parse {"bytes":123,"time":0.123} into numbers
local function parse_json_bytes_time(s)
	local b = s:match('"bytes"%s*:%s*(%d+)')
	local t = s:match('"time"%s*:%s*([%d%.]+)')
	return tonumber(b) or 0, tonumber(t) or 0.0
end

local function calc_mbit(bytes, seconds)
	if not seconds or seconds <= 0 then
		return 0.0
	end
	return (bytes / seconds) * 8.0 / 1000000.0
end

local function fmt(v)
	return string.format("%.2f", v or 0)
end

-- ------------ Download test ------------
local dl_bytes, dl_time = 0, 0.0

for _, url in ipairs(DOWNLOAD_URLS) do
	local cmd = string.format(
		"curl -4 -L -o /dev/null -s "
			.. "--max-time 20 "
			.. "-w '{\"bytes\":%%{size_download},\"time\":%%{time_total}}' '%s' "
			.. '|| echo \'{"bytes":0,"time":0}\'',
		url
	)
	local json = run_cmd(cmd)
	local b, t = parse_json_bytes_time(json)
	if b > 0 then
		dl_bytes, dl_time = b, t
		break
	end
end

local dl_mbit = 0.0
if dl_bytes > 0 then
	dl_mbit = calc_mbit(dl_bytes, dl_time)
end

-- ------------ Upload test ------------
-- Generate UPLOAD_SIZE bytes from /dev/zero and pipe to curl
local cmd_upload = string.format(
	"dd if=/dev/zero bs=%d count=1 2>/dev/null | "
		.. "curl -4 -s -o /dev/null --max-time 20 "
		.. '-w \'{"bytes":%%{size_upload},"time":%%{time_total}}\' '
		.. "-X POST --data-binary @- '%s' "
		.. '|| echo \'{"bytes":0,"time":0}\'',
	UPLOAD_SIZE,
	UPLOAD_URL
)

local ul_json = run_cmd(cmd_upload)
local ul_bytes, ul_time = parse_json_bytes_time(ul_json)

local ul_mbit = 0.0
if ul_bytes > 0 then
	ul_mbit = calc_mbit(ul_bytes, ul_time)
end

-- ------------ Influx line ------------
local line = string.format("internet_speed,host=%s download_mbps=%s,upload_mbps=%s", HOST, fmt(dl_mbit), fmt(ul_mbit))

print(line)
