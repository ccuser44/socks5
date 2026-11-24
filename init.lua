local ffi = require("ffi")
local net = require("net")
local tls = require("tls")
local url = require("url")
local json
do
	local success, cjson = pcall(require, "cjson")
	json = success and cjson or require("json")
end
local strext = require("string-extensions")
local sbuff = require("sbuff")

pcall(require, "table.new") -- LuaJIT support
pcall(require, "table.clear") -- LuaJIT support

if not table.clone then -- TODO: Convert to seperate library
	function table.clone(t)
		local copy = table.new(#t, 0)
		for k, v in pairs(t) do
			copy[k] = v
		end
		return copy
	end
end

local readSocket, writeSocket, connectSocket, disconnectSocket = sbuff.readSocket, sbuff.writeSocket, sbuff.connectSocket, sbuff.disconnectSocket
local combineInt, ipv6ToInts

local DEFAULT_PORT = 1080
local VERSION_MAP = {
	socks5 = 0x5,
	socks5h = 0x5,
	socks4a = 0x4A,
	socks4 = 0x4,
}
local STATUS_MESSAGES = setmetatable({
	[0x00] = "request granted",
	[0x01] = "general failure",
	[0x02] = "connection not allowed by ruleset",
	[0x03] = "network unreachable",
	[0x04] = "host unreachable",
	[0x05] = "connection refused by destination host",
	[0x06] = "TTL expired",
	[0x07] = "command not supported / protocol error",
	[0x08] = "address type not supported",
}, { __index = function(_, k) return "Unknown Error: " .. tostring(k) end })
local DEFAULT_SUPPORTED = {0x0, --[[0x1,]] 0x2, 0x3, 0x6}
local METHOD_PREFERENCE = {0x6, 0x3, 0x2, 0x0, 0x1}
local PASSWORD_METHODS = {0x1, 0x2, 0x3}

local methods = setmetatable({
	[0x0] = function() -- // No auth
		-- // Do nothing
	end,
	[0x1] = function() -- // GSSAPI
		-- // Probably not supported ever??!?!?
	end,
	[0x2] = function(socket, options, buff) -- // Username&Password
		--print(options.name, options.pass)
		writeSocket(socket, ">b s1 s1", 0x1, tostring(options.name), tostring(options.pass))
		local ver, success = readSocket(socket, ">b b", buff)
		assert(ver == 0x1, "Unsupported server auth version!")
		assert(success == 0, "Authentification failed!")
	end,
	-- IANA methods
	[0x3] = function(socket, options, buff) -- // CHAP -- https://datatracker.ietf.org/doc/html/draft-ietf-aft-socks-chap
		local ver, navas = readSocket(socket, ">B B", buff)
		local attributes = {readSocket(socket, string.rep(">b s1", navas), buff)}

		-- TODO: Finish CHAP support
	end,
	[0x6] = function(socket, options, buff) -- // SSL/TLS
		disconnectSocket(socket)
		local mock = table.clone(options)
		mock.host, mock.port = mock.proxy, mock.proxyPort
		options.socket = assert(tls.connect(mock), "TLS socket creation failed!")
		connectSocket(options.socket)
	end,
	[0x9] = function(socket, options, buff) -- JSON Parameter Block
		writeSocket(socket, ">s4", assert(type(options.authparams) == "string" and options.authparams or options.authparams and json.encode(options.authparams), "No JSON parameters specified to client!"))
		-- TODO: Investigate the error code handling
	end,
	-- // No other methods will be supported!!
	[0xFF] = function()
		error("Server doesn't support any valid authentication methods")
	end,
}, { __index = function(self, k)
	return self[0xFF]
end })

-- TODO: Move this to using completely a callback based state machine! No yielding.

local function lookupify(tbl)
	local tbl2 = {}

	for i, v in pairs(tbl) do
		tbl2[v] = i
	end

	return tbl2
end

local function toUint32(x)
	if x < 0 then
		return x + 2^32
	end
	return x
end

combineInt = function(t, size, i, j, inc, base)
	size = size or 8
	local n = 0

	for i2 = i or 1, j or #t, inc or 1 do
		local num = tonumber(t[#t + 1 - i2], base)

		if num then
			n = bit.bor(bit.lshift(num, size * (i2 - 1)), n)
		else
			return
		end
	end

	return toUint32(n)
end

ipv6ToInts = function(ip)
	ip = string.split(string.match(ip, "^%s*%[?(.-)%]?%s*$"), ":")

	for i = #ip, 1, -1 do
		if ip[i] == "" then
			if i == 1 or i == #ip then
				ip[i] = 0
			else
				local new = 8 - #ip
				table.move(ip, i + 1, #ip, i + new)
				for i2 = i, i + new do
					ip[i2] = 0
				end
			end
		end
	end

	return combineInt(ip, 16, 1, 2, 1, 16), combineInt(ip, 16, 3, 4, 1, 16), combineInt(ip, 16, 5, 6, 1, 16), combineInt(ip, 16, 7, 8, 1, 16)
end

local function createServer(options, callback)

end

local function connect(port, ...)
	local args = table.pack(...)
	local options = {}
	local rawIp, cmdType = nil, 0x1

	-- future proof
	if type(port) == "table" then
		options = port
		options.callback = args[1]
	else
		options.port = port
		options.host, options.callback = args[1], args[2]
		options.proxy, options.proxyPort = args[3], args[4]
	end

	do
		local data = url.parse(assert(options.proxy, "Missing proxy!"))
		options.protocol = data.protocol
		options.proxyPort, options.proxy = options.proxyPort or data.port or DEFAULT_PORT, data.hostname
		cmdType = options.host:upper() == "UDP" and 0x3 or options.host:upper() == "BIND" and 0x2 or 0x1 -- TODO: Add a UDP binding support wrapper

		if cmdType ~= 0x1 then
			options.host = options.proxy
		end

		if data.auth then
			local name, pass = string.match(data.auth, "^%s*([^:]+):?(.-)%s*$")

			options.name, options.pass = name or options.name, pass or options.pass
		end
	end

	if type(assert(options.host, "Missing host!")) == "string" then
		local data = url.parse(options.host)
		options.port, options.hostname = assert(data.port or options.port, "Missing port!"), data.host
	else
		rawIp = options.host
		options.hostname = tostring(bit.band(bit.rshift(rawIp, 24), 0xFF)) .. "." .. tostring(bit.band(bit.rshift(rawIp, 16), 0xFF)) .. "." .. tostring(bit.band(bit.rshift(rawIp, 8), 0xFF)) .. "." .. tostring(bit.band(rawIp, 0xFF))
	end

	local origVer = options.protocol and VERSION_MAP[string.lower(options.protocol)]
	options.socket = options.socket or net.createConnection(options.proxyPort, options.proxy)
	options.buff = table.new(32, 1)
	options.buff.strlen = 0
	connectSocket(options.socket, options.buff)

	-- // Greeting
	sbuff.assertCoroutine(coroutine.yield())
	writeSocket(options.socket, ">b s1", 0x5, string.char(table.unpack(options.methods or lookupify(DEFAULT_SUPPORTED))))
	local ver, method = readSocket(options.socket, ">B B", options.buff)

	if ver ~= 0x5 then
		error("UNIMPLEMENTED PROXY VERSIONS!")
		-- // Handle other SOCKS versions
	end

	methods[method].client(options.socket, options, options.buff) -- TODO: Make this support the SSL thing, also add SOCKS4 proxy support

	-- // Connection request
	rawIp = rawIp or not string.find(options.hostname, "%a") and combineInt(string.split(options.hostname, "."))
	local isIpv6 = string.find(options.hostname, ":", 1, true) and string.find(string.sub(options.hostname, 1, select(2, string.find(options.hostname, "^.+:")) - 1), ":", 1, true)
	local address = rawIp and string.pack(">b L", 0x1, rawIp) or isIpv6 and string.pack(">b LLLL", 0x4, ipv6ToInts(options.hostname)) or string.pack(">b s1", 0x3, options.hostname)
	writeSocket(options.socket, ">b b b c" .. #address .. " H", 0x5, cmdType, 0x0, address, options.port)

	-- // Connection response handling
	local ver, status, rsv, addTyp = readSocket(options.socket, ">bbbb", options.buff)
	assert(status == 0x0, STATUS_MESSAGES[status])
	assert(addTyp == 0x1 or addTyp == 0x3 or addTyp == 0x4, "Unrecognized address type!")
	local checkAddr = addTyp == 0x1 and readSocket(options.socket, ">L", options.buff) or addTyp == 0x4 and string.format(string.rep("%x0", 8, ":"), readSocket(options.socket, ">HH HH HH HH")) or addTyp == 0x3 and readSocket(options.socket, ">s1", options.buff)
	local checkPort = readSocket(options.socket, ">H", options.buff)

	return disconnectSocket(options.socket), checkAddr, checkPort
end

METHOD_PREFERENCE, DEFAULT_SUPPORTED = lookupify(METHOD_PREFERENCE), lookupify(DEFAULT_SUPPORTED)

for method, v in pairs(methods) do
	if type(v) == "function" then
		methods[method] = { client = v, server = v }
	elseif not v.client then
		v.client = v.server
	elseif not v.server then
		v.server = v.client
	end
end

return {
	connect = connect,
	createServer = createServer,
}
