local strext = require("string-extensions")

local ENABLE_DEBUGGING = false
local CONN_TERM = "Connection terminated due to: "
local MAX_ERRORS = 64
local REGISTERED_HANDLERS = { "connect", "data", "end", "error", "close" }

local function assertCoroutine(status, err)
	if not status then
		error(CONN_TERM .. tostring(err), 2)
	else
		return status, err
	end
end

local function readBuffLen(buff, n)
	while buff.strlen < n do
		coroutine.yield()
	end

	local raw = table.concat(buff)
	table.clear(buff)
	local result = raw:sub(1, n)
	table.insert(buff, raw:sub(n + 1))
	buff.strlen = #buff[1]

	return result
end

local function findNullStr(buff, last)
	for i = last + 1, #buff do
		local found = string.find(assert(buff[i]), "%z", 1, true)

		if found then
			for i2 = 1, i - 1 do
				found = found + #buff[i2]
			end

			return i, found
		end
	end

	return #buff, nil
end

local function readBuffStr(buff)
	local checkIdx, foundIdx = findNullStr(buff, 0)

	while not foundIdx do
		assertCoroutine(coroutine.yield())
		checkIdx, foundIdx = findNullStr(buff, checkIdx)
	end

	return readBuffLen(buff, foundIdx)
end

local function writeSocket(self, schema, ...)
	assert(not self.destroyed, "Cannot write to a closed socket!") -- Prevent a really granly LibUV bug where writing to a closed socket causes a hard to debug program crash
	self:write(string.pack(schema, ...))
end

local function readSocket(self, schema, buff)
	assert(not self.destroyed, "Cannot write to a closed socket!") -- Prevent a really granly LibUV bug where writing to a closed socket causes a hard to debug program crash
	local schemas = string.split(schema, "s")
	local data = table.new(#schemas + #schema - #string.gsub(schema, "z", ""), 0)
	local endian = ""
	local totalLen = 0

	for idx, str in ipairs(schemas) do
		for i, v in ipairs(string.split(str, "z")) do
			if i > 2 then
				table.insert(data, readBuffStr(buff))
			end

			endian = string.match(v, ".*([<>=])") or endian
			local slen = i <= 1 and idx > 1 and endian .. (string.match(v, "^%s*(%d+)") and "I" .. string.match(v, "^%s*(%d+)") or "T")
			table.insert(data, readBuffLen(buff, string.packsize(slen and "c" .. tostring(string.unpack(readBuffLen(buff, string.packsize(slen)), slen)) .. string.gsub(v, "^%s*%d+", "") or v)))
		end
	end

	return string.unpack(schema, table.concat(data))
end

local function connectSocket(socket, buff)
	local co, errors = assert(coroutine.running(), "No available co-routine to buffer packets"), 0

	socket:on("connect", function()
		if ENABLE_DEBUGGING then
			print("CONNECTED")
		end

		coroutine.resume(co, true)
		errors = 0
	end)

	socket:on("data", function(data)
		if ENABLE_DEBUGGING then
			print("received data:", string.format(string.rep("%02x", #data, " "), string.byte(data, 1, #data)), "len:", #data)
		end

		table.insert(buff, data)
		buff.strlen, errors = buff.strlen + #data, 0
		coroutine.resume(co, true)
	end)

	socket:on("end", function()
		if ENABLE_DEBUGGING then
			print("client disconnected")
		end

		coroutine.resume(co, false, "Connection ended")
		socket:destroy()
	end)

	socket:on("error", function(err)
		if ENABLE_DEBUGGING then
			print("socket error:", err)
		end

		errors = errors + 1

		if errors > MAX_ERRORS then -- Hande errors gracefully but if it's stuck then
			coroutine.resume(co, false, err)
			socket:destroy()
		end
	end)

	socket:on("close", function()
		if ENABLE_DEBUGGING then
			print("CLOSE")
		end

		coroutine.resume(co, false, "Connection closed")
		socket:destroy()
	end)
end

local function disconnectSocket(socket)
	for _, v in ipairs(REGISTERED_HANDLERS) do
		pcall(socket.removeListener, socket, v)
	end

	return socket
end

return {
	writeSocket = writeSocket,
	readSocket = readSocket,
	connectSocket = connectSocket,
	disconnectSocket = disconnectSocket,
	assertCoroutine = assertCoroutine
}
