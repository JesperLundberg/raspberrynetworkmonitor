#!/usr/bin/env luajit

-- Count unique active LAN devices using arp-scan.
-- - Ignores duplicate lines like "(DUP: 2)"
-- - Ensures the host itself is counted
-- Outputs one InfluxDB line: net_active_devices count=<N>

local INTERFACE = os.getenv("ARP_SCAN_IFACE") or "eth0"

local function run_cmd(cmd)
	local f = io.popen(cmd, "r")
	if not f then
		return ""
	end
	local out = f:read("*a") or ""
	f:close()
	return out
end

-- Get the IPv4 address of the given interface (e.g. eth0)
local function get_self_ip(iface)
	-- Example line from `ip -4 addr show dev eth0`:
	--   inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0
	local cmd = string.format("ip -4 addr show dev %s 2>/dev/null", iface)
	local out = run_cmd(cmd)
	local ip = out:match("inet%s+(%d+%.%d+%.%d+%.%d+)/%d+")
	return ip
end

-- Run arp-scan for the local network
local function scan_devices(iface)
	local cmd = string.format("arp-scan --localnet --interface=%s 2>/dev/null", iface)
	local out = run_cmd(cmd)

	local seen = {} -- set of unique IPs
	for line in out:gmatch("[^\r\n]+") do
		local ip = line:match("^(%d+%.%d+%.%d+%.%d+)")
		if ip then
			-- Deduplicate by IP, so DUP lines and repeats don't matter
			seen[ip] = true
		end
	end

	return seen
end

-- Build set of IPs from arp-scan
local seen = scan_devices(INTERFACE)

-- Ensure we also count the host itself
local self_ip = get_self_ip(INTERFACE)
if self_ip and self_ip ~= "" then
	seen[self_ip] = true
end

-- Count unique IPs
local count = 0
for _ in pairs(seen) do
	count = count + 1
end

-- InfluxDB line protocol output
print(string.format("net_active_devices count=%d", count))
