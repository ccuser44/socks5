local http = require("http")
local socks5 = require("./")

for proxy in io.lines("./proxies.txt") do
	proxy = string.match(proxy, "^%s*(.-)%s*$")

	if proxy ~= "" then
		local success, err = pcall(socks5.connect, {
			proxyPort = nil,
			proxy = proxy,
			host = "https://google.com",
			port = 443,
		})

		if success and err then
			print("SUCCESSFULLY CONNECTED TO:", proxy)
		else
			print("PROXY CONNECTION FAILED! REASON", err)
		end
	end
end

print("FINISHED TEST!")
os.exit()
