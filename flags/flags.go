package flags

import (
	"crypto/cipher"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/sagan/simplegoproxy/constants"
)

const DEFAULT_PORT = 8380 // ASCII (Decimal) 'SP' (83 + 80)

var (
	ConfigFile          string // custom config file path
	Addr                string
	Sign                bool
	Parse               bool
	Log                 bool
	Encrypt             bool
	Cors                bool
	BasicAuth           bool
	EnableUnix          bool
	EnableFile          bool
	EnableRclone        bool
	EnableCurl          bool
	EnableExec          bool
	Prod                bool
	OpenNormal          bool
	SupressError        bool
	RcloneBinary        string
	RcloneConfig        string
	CurlBinary          string
	Rootpath            string
	Adminpath           string
	Prefix              string
	Eid                 string
	Key                 string
	Keytype             string
	PublicUrl           string
	KeytypeBlacklistStr string
	User                string
	Pass                string
	KeytypeBlacklist    []string
	OpenScopes          ArrayFlags // scopes that do NOT need signing
	Aliases             ArrayFlags // each alias format: "prefix=path"

	Cipher cipher.AEAD
)

type ArrayFlags []string

func (i *ArrayFlags) String() string {
	return fmt.Sprint([]string(*i))
}

func (i *ArrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func init() {
	flag.StringVar(&ConfigFile, "config", "",
		`Config file name (toml format). Default is "~/.config/sgp/sgp.toml". Set to "`+constants.NONE+
			`" to suppress default config file`)
	flag.StringVar(&Addr, "addr", fmt.Sprintf("0.0.0.0:%d", DEFAULT_PORT),
		fmt.Sprintf(`Http listening addr, e.g. "127.0.0.1:%d" or ":%d" or just "%d" (port only). If not set, will listen on "0.0.0.0:%d"`,
			DEFAULT_PORT, DEFAULT_PORT, DEFAULT_PORT, DEFAULT_PORT))
	flag.BoolVar(&Log, "log", false, "Log every request urls")
	flag.BoolVar(&SupressError, "supress-error", false, "Supress error display, send a 404 to client instead")
	flag.BoolVar(&Encrypt, "encrypt", false, `Used with "-sign", encrypt generated entrypoint url`)
	flag.BoolVar(&Parse, "parse", false, `Parse entrypoint url(s), display original target urls`)
	flag.BoolVar(&EnableUnix, "enable-unix", false,
		`Enable unix domain socket url: "unix:///path/to/socket:http://server/path"`)
	flag.BoolVar(&EnableFile, "enable-file", false, `Enable file scheme url: "file:///path/to/file"`)
	flag.BoolVar(&EnableRclone, "enable-rclone", false, `Enable rclone scheme url: "rclone://remote/path/to/file"`)
	flag.BoolVar(&EnableExec, "enable-exec", false, `Enable exec scheme url: "exec:///path/to/bin?arg=foo&arg=bar"`)
	flag.BoolVar(&EnableCurl, "enable-curl", false, `Enable "curl+*" scheme url: "curl+https://ipinfo.io"`)
	flag.BoolVar(&Prod, "prod", false, `Production mode: enable all schemes, supress error, force signing`)
	flag.BoolVar(&OpenNormal, "open-normal", false, `Used with request signing, make all "http(s)" and "data" urls do not require signing`)
	flag.BoolVar(&Cors, "cors", false, `Set "Access-Control-Allow-Origin: *" header for admin API`)
	flag.BoolVar(&BasicAuth, "basic-auth", false,
		`Make admin UI use http basic authentication. If not set, it uses Digest authentication (more secure)`)
	flag.BoolVar(&Sign, "sign", false,
		`Calculate the sign of target url and output result. The "key" flag need to be set. Args are url(s)`)
	flag.StringVar(&Eid, "eid", "",
		`Used with "-sign -encrypt". Encrypted url id, it will appear at the start of generated encrypted entrypoint utl`)
	flag.StringVar(&RcloneBinary, "rclone-binary", "rclone", "Rclone binary path")
	flag.StringVar(&CurlBinary, "curl-binary", "curl", "Curl binary path")
	flag.StringVar(&RcloneConfig, "rclone-config", "", "Manually specify rclone config file path")
	flag.StringVar(&Rootpath, "rootpath", "/", "Root path (with leading and trailing slash)")
	flag.StringVar(&Adminpath, "adminpath", "", `Admin UI path. Default is <rootpath> + "admin/"`)
	flag.StringVar(&PublicUrl, "publicurl", "",
		`Public url of this service. Used with "-sign". E.g. "https://sgp.example.com/". `+
			`If set, will output the full generated entrypoint url instead of sign`)
	flag.StringVar(&Prefix, "prefix", "_sgp_", "Prefix of settings in query parameters")
	flag.StringVar(&User, "user", "root", `Username of admin UI (Admin UI is available at "adminpath")`)
	flag.StringVar(&Pass, "pass", "", `Password of admin UI. If not set, the "key" will be used`)
	flag.StringVar(&Key, "key", "", "The sign key. If set, all requests must be signed using HMAC(key, 'sha-256', payload=url), providing calculated MAC (hex string) in _sgp_sign")
	flag.StringVar(&Keytype, "keytype", "", `The sign keytype. Used with "-sign"`)
	flag.StringVar(&KeytypeBlacklistStr, "keytypebl", "", "Comma-separated list of blacklisted keytypes")
	flag.Var(&OpenScopes, "open-scope", `Used with request signing. Array list. Public scopes that urls of these scopes do not require signing. E.g. "http://example.com/*"`)
	flag.Var(&Aliases, "alias", `Aliases. Array List. Each one format: "prefix=path"`)
}

// Parse flags from command line args, env, and config files.
// It calls log.Fatalf if encounters any error.
func DoParse() {
	var flagSet = map[string]bool{}                      // whether a flag is already set
	var arrayFlagNames = []string{"open-scope", "alias"} // Names list of flags which is of array type.
	var configFileLoaded = false

	// First, read from command line.
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		flagSet[f.Name] = true
	})

	// Then, read config file that is declared on the command line.
	if ConfigFile != "" {
		if ConfigFile != constants.NONE {
			parseFromConfigFile(ConfigFile, arrayFlagNames, flagSet)
		}
		configFileLoaded = true
	}

	// Next, read from environment variables.
	flag.VisitAll(func(f *flag.Flag) {
		if flagSet[f.Name] {
			return
		}
		envname := constants.SGP_ENV_PREFIX + strings.ReplaceAll(strings.ToUpper(f.Name), "-", "_")
		envValue := os.Getenv(envname)
		if envValue == "" {
			return
		}
		flagSet[f.Name] = true
		if !slices.Contains(arrayFlagNames, f.Name) {
			if err := f.Value.Set(envValue); err != nil {
				log.Fatalf("Failed to set %s flag to %q from env %s: %v", f.Name, envValue, envname, err)
			}
		} else {
			values := strings.Split(envValue, ";")
			for _, value := range values {
				if value = strings.TrimSpace(value); value != "" {
					if err := f.Value.Set(value); err != nil {
						log.Fatalf("Failed to set array flag %s value %q", f.Name, value)
					}
				}
			}
		}
	})

	// Last, read from global config file, or config file set via SGP_CONFIG env.
	if !configFileLoaded {
		if ConfigFile == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("User home dir not found: %v", err)
			}
			configFile := filepath.Join(homeDir, ".config/sgp/sgp.toml")
			if _, err := os.Stat(configFile); err == nil {
				ConfigFile = configFile
			} else if !errors.Is(err, fs.ErrNotExist) {
				log.Fatalf("Failed to access global config file %q: %v", configFile, err)
			}
		}
		if ConfigFile != "" {
			if ConfigFile != constants.NONE {
				parseFromConfigFile(ConfigFile, arrayFlagNames, flagSet)
			}
			configFileLoaded = true
		}
	}
}

func parseFromConfigFile(configFile string, arrayFlagNames []string, flagSet map[string]bool) {
	log.Printf("Read config file %q", configFile)
	configFileContents, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}
	var configMap map[string]any
	if err = toml.Unmarshal(configFileContents, &configMap); err != nil {
		log.Fatalf("Failed to parse config file as toml: %v", err)
	}
	if configMap == nil {
		return
	}
	if env, ok := configMap["env"]; ok {
		envMap, ok := env.(map[string]any)
		if !ok {
			log.Fatalf("Config file 'env' field invalid type: %T", env)
		}
		for key, value := range envMap {
			strvalue, ok := value.(string)
			if !ok {
				log.Fatalf("env field must be string: %T", value)
			}
			if err := os.Setenv(key, strvalue); err != nil {
				log.Fatalf("Failed to set env %q value: %q", key, err)
			}
		}
	}
	flag.VisitAll(func(f *flag.Flag) {
		if flagSet[f.Name] {
			return
		}
		configkey := strings.ReplaceAll(strings.ToLower(f.Name), "-", "_")
		value, ok := configMap[configkey]
		if !ok {
			return
		}
		flagSet[f.Name] = true
		if slices.Contains(arrayFlagNames, f.Name) {
			arrvalue, ok := value.([]any)
			if !ok {
				log.Fatalf("invalid config file %q field: invalid type: %T", f.Name, value)
			}
			for _, v := range arrvalue {
				strvalue, ok := v.(string)
				if !ok {
					log.Fatalf("%q field element must be string: %T", f.Name, v)
				}
				if err := f.Value.Set(strvalue); err != nil {
					log.Fatalf("Failed to set %q to %v: %v", f.Name, strvalue, err)
				}
			}
		} else {
			switch v := value.(type) {
			case string:
				err = f.Value.Set(v)
			case int:
				err = f.Value.Set(fmt.Sprint(v))
			case int64:
				err = f.Value.Set(fmt.Sprint(v))
			case bool:
				err = f.Value.Set(fmt.Sprint(v))
			default:
				err = fmt.Errorf("invalid type: %T", v)
			}
			if err != nil {
				log.Fatalf("invalid config file %q field: %v", f.Name, err)
			}
		}
	})
}
