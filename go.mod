module github.com/sagan/simplegoproxy

go 1.21.0

// workaround for https://github.com/Noooste/azuretls-client/issues/27
replace github.com/Noooste/azuretls-client v1.2.5 => github.com/sagan/azuretls-client v0.0.0-20240110021915-00703735ede6

require github.com/Noooste/azuretls-client v1.2.5

require (
	github.com/Noooste/fhttp v1.0.6 // indirect
	github.com/Noooste/utls v1.2.4 // indirect
	github.com/Noooste/websocket v1.0.1 // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/quic-go/quic-go v0.40.1 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)
