package flags

import "flag"

var (
	Port                int
	Sign                bool
	Log                 bool
	Cors                bool
	EnableUnix          bool
	EnableFile          bool
	EnableRclone        bool
	EnableCurl          bool
	EnableExec          bool
	EnableAll           bool
	RcloneBinary        string
	RcloneConfig        string
	CurlBinary          string
	Rootpath            string
	Prefix              string
	Key                 string
	Keytype             string
	PublicUrl           string
	KeytypeBlacklistStr string
	User                string
	Pass                string
	KeytypeBlacklist    []string
)

func init() {
	flag.IntVar(&Port, "port", 3000, "Http listening port")
	flag.BoolVar(&Log, "log", false, "Log every request urls")
	flag.BoolVar(&EnableUnix, "enable-unix", false, `Enable unix domain socket url: "unix:///path/to/socket:http://server/path"`)
	flag.BoolVar(&EnableFile, "enable-file", false, `Enable file scheme url: "file:///path/to/file"`)
	flag.BoolVar(&EnableRclone, "enable-rclone", false, `Enable rclone scheme url: "rclone://remote/path/to/file"`)
	flag.BoolVar(&EnableExec, "enable-exec", false, `Enable exec scheme url: "exec:///path/to/bin?arg=foo&arg=bar"`)
	flag.BoolVar(&EnableCurl, "enable-curl", false, `Enable "curl+*" scheme url: "curl+https://ipinfo.io"`)
	flag.BoolVar(&EnableAll, "enable-all", false, `Enable all schemes url: unix & file & rclone & curl & exec`)
	flag.BoolVar(&Cors, "cors", false, `Set "Access-Control-Allow-Origin: *" header for admin API`)
	flag.BoolVar(&Sign, "sign", false,
		`Calculate the sign of target url and output result. The "key" flag need to be set. Args are url(s)`)
	flag.StringVar(&RcloneBinary, "rclone-binary", "rclone", "Rclone binary path")
	flag.StringVar(&CurlBinary, "curl-binary", "curl", "Curl binary path")
	flag.StringVar(&RcloneConfig, "rclone-config", "", "Manually specify rclone config file path")
	flag.StringVar(&Rootpath, "rootpath", "/", "Root path (with leading and trailing slash)")
	flag.StringVar(&PublicUrl, "publicurl", "",
		`Public url of this service. Used with "-sign". E.g. "https://sgp.example.com/". `+
			`If set, will output the full generated entrypoint url instead of sign`)
	flag.StringVar(&Prefix, "prefix", "_sgp_", "Prefix of settings in query parameters")
	flag.StringVar(&User, "user", "root", `Username of admin UI (Admin UI is available at "/admin" path)`)
	flag.StringVar(&Pass, "pass", "", `Password of admin UI. If not set, the "key" will be used`)
	flag.StringVar(&Key, "key", "", "The sign key. If set, all requests must be signed using HMAC(key, 'sha-256', payload=url), providing calculated MAC (hex string) in _sgp_sign")
	flag.StringVar(&Keytype, "keytype", "", `The sign keytype. Used with "-sign"`)
	flag.StringVar(&KeytypeBlacklistStr, "keytypebl", "", "Comma-separated list of blacklisted keytypes")
}
