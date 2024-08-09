package flags

import "flag"

var (
	Port                int
	Sign                bool
	Log                 bool
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
	flag.BoolVar(&Sign, "sign", false, `Calculate the sign of target url and output result. The "key" flag need to be set. Args are url(s)`)
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
