return {
	name = "ccuser44/socks5",
	version = "1.0.0",
	description = "A full SOCKS5, SOCKS4a and SOCKS4 client and server implementation in luvit.",
	tags = { "proxy", "proxies", "socks", "socks5", "socks4a", "socks4", "socket" },
	license = "MIT",
	author = { name = "ccuser44", email = "68124053+ccuser44@users.noreply.github.com" },
	homepage = "https://github.com/ccuser44/socks5",
	dependencies = {
		"Richy-Z/string-extensions"
	},
	files = {
		"**.lua",
		"!**spec.lua",
		"!test*",
		"!tempinfo/**"
	}
}
