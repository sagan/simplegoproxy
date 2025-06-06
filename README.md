## simplegoproxy

Simplegoproxy is a http / API proxy that can, and is designed and intended to be used to modify the http request headers, response headers and / or response body on the fly, based on custom rules per request, and then return the modified response to the user.

Simply put, Simplegoproxy generates an "entrypoint url", which can be accessed (GET) to make an arbitrary request to the "target url" (All aspects of the Request or Response can be set or modified), and returns the final result (modified Response) to the user.

Basically, the "target url" is a http(s) url, but it also supports some special customary scheme urls. E.g. the `exec://` urls, which execute a local program and send it's output back to the client as http response.

Use cases:

- Remove CORS restrictions.
- Add "Authorization" or other headers to the request.
- Apply string replacements on the response body.

TOC

- [simplegoproxy](#simplegoproxy)
- [Run](#run)
- [Usage](#usage)
- [Modification parameters](#modification-parameters)
- [Features](#features)
  - [Modification parameters fronting](#modification-parameters-fronting)
  - [Response body substitutions](#response-body-substitutions)
  - [Impersonate the Browser](#impersonate-the-browser)
  - [Response template](#response-template)
    - [The template context](#the-template-context)
    - [Template mode](#template-mode)
    - [Template examples](#template-examples)
    - [JavaScript template](#javascript-template)
  - [Admin UI](#admin-ui)
  - ["data:" urls](#data-urls)
  - [`unix://`, `file://`, `rclone://`, `curl+*//`, `exec://` urls](#unix-file-rclone-curl-exec-urls)
  - [URL Aliases](#url-aliases)
- [Security features](#security-features)
  - [Set the rootpath](#set-the-rootpath)
  - [Request signing](#request-signing)
  - [Admin UI Authorization](#admin-ui-authorization)
  - [Env substitutions](#env-substitutions)
  - [Signing key type](#signing-key-type)
  - [Scope signing](#scope-signing)
  - [Open scopes](#open-scopes)
  - [URL encryption](#url-encryption)
  - [Request authentication](#request-authentication)
  - [Response encryption](#response-encryption)
    - [Encryption mode \& parameters](#encryption-mode--parameters)
    - [Public key encryption mode](#public-key-encryption-mode)
    - [Local signing](#local-signing)
    - [Encryption best practive](#encryption-best-practive)
    - [How to decrypt](#how-to-decrypt)
  - [Referer restrictions](#referer-restrictions)
  - [Origin restrictions](#origin-restrictions)
  - [Error Suppressions and Logging](#error-suppressions-and-logging)

## Run

Simplegoproxy is written in Go and published as a single executable file which requires no mandatory argument.

You can also run it using Docker:

```
docker run --name sgp -p 8380:8380 -d \
  ghcr.io/sagan/simplegoproxy
```

Command-line flag arguments:

```
  -addr string
        Http listening addr, e.g. "127.0.0.1:8380" or ":8380" or just "8380" (port only). If not set, will listen on "0.0.0.0:8380" (default "0.0.0.0:8380")
  -adminpath string
        Admin UI path. Default is <rootpath> + "admin/". Set to "none" to disable admin ui
  -alias value
        Aliases. Array List. Each one format: "prefix=path"
  -basic-auth
        Make admin UI use http basic authentication. If not set, it uses Digest authentication (more secure)
  -config string
        Config file name (toml format). Default is "~/.config/sgp/sgp.toml". Set to "none" to suppress default config file
  -cors
        Set "Access-Control-Allow-Origin: *" header for admin API
  -curl-binary string
        Curl binary path (default "curl")
  -eid string
        Used with "-sign -encrypt". Encrypted url id, it will appear at the start of generated encrypted entrypoint utl
  -enable-curl
        Enable "curl+*" scheme url: "curl+https://ipinfo.io"
  -enable-exec
        Enable exec scheme url: "exec:///path/to/bin?arg=foo&arg=bar"
  -enable-file
        Enable file scheme url: "file:///path/to/file"
  -enable-rclone
        Enable rclone scheme url: "rclone://remote/path/to/file"
  -enable-unix
        Enable unix domain socket url: "unix:///path/to/socket:http://server/path"
  -encrypt
        Used with "-sign", encrypt generated entrypoint url
  -key string
        The sign key. If set, all requests must be signed using HMAC(key, 'sha-256', payload=url), providing calculated MAC (hex string) in _sgp_sign
  -keytype string
        The sign keytype. Used with "-sign"
  -keytypebl string
        Comma-separated list of blacklisted keytypes
  -log
        Log every request urls
  -open-normal
        Used with request signing, make all "http(s)" and "data" urls do not require signing
  -open-scope value
        Used with request signing. Array list. Public scopes that urls of these scopes do not require signing. E.g. "http://example.com/*"
  -parse
        Parse entrypoint url(s), display original target urls
  -pass string
        Password of admin UI. If not set, the "key" will be used
  -prefix string
        Prefix of settings in query parameters (default "_sgp_")
  -prod
        Production mode: enable all schemes, supress error, force signing
  -publicurl string
        Public url of this service. Used with "-sign". E.g. "https://sgp.example.com/". If set, will output the full generated entrypoint url instead of sign
  -rclone-binary string
        Rclone binary path (default "rclone")
  -rclone-config string
        Manually specify rclone config file path
  -rootpath string
        Root path (with leading and trailing slash) (default "/")
  -sign
        Calculate the sign of target url and output result. The "key" flag need to be set. Args are url(s)
  -sitename string
        The site name (default "SGP")
  -supress-error
        Supress error display, send a 404 to client instead
  -user string
        Username of admin UI (Admin UI is available at "adminpath") (default "root")
```

All flags are optional, and can also be set by environment variable. The environment variable name is the `SGP_` prefix concating flag name in uppercase and replacing `-` with `_`. E.g.: `enable-file` flag can be set by setting `SGP_ENABLE_FILE=true` env. For the array list type flags like `-open-scope`, the env value should be all array item values joined by `;`.

Alternatively, you can set flags using `~/.config/sgp/sgp.toml` config file, where `~` is the user home dir of current OS. Example config file:

```toml
addr = 8382
enable_file = true

alias = [
  "/ip/=/_sgp_cors=/ipinfo.io/"
]

[env]
SECRET = "abc"
```

Notes:

- The variable name in config file is the lowercase flag name with `-` replaced by `_`.
- The config file path can be explicitly specified via `-config=<value>` command line flag.
- The `env` is a config-file-specific variable that can be used to set environment variables of Simplegoproxy process.

## Usage

Append the target url to the root path to generate the "entrypoint url". E.g.: (Assume Simplegoproxy is started with the default "/' root path):

```
curl -i "localhost:8380/https://ipcfg.co/json"

# The scheme:// part of target url can be omitted, in which case "https://" is assumed
curl -i "localhost:8380/ipcfg.co/json"
```

The "entrypoint url" accepts http requests. By default it will just fetch the "target url" and return the original response, without any modification. Add specic query parameters to set the modification rules. E.g.:

```
curl -i "localhost:8380/https://ipcfg.co/json?_sgp_cors"
```

The `_sgp_cors` modification parameter indicates Simplegoproxy to modify the original response headers to set the CORS-allow-all headers:

```
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, OPTIONS
Access-Control-Allow-Origin: *
```

## Modification parameters

All modification paramaters has the `_sgp_` prefix by default, which can be changed via `-prefix` command-line argument.

The "Array Value" type parameters can be set multiple times; alternatively, multiple values can be put in single parameter via joining these values by `,`.

- `_sgp_cors` : (Value ignored) Add the CORS-allow-all headers to original response.
- `_sgp_nocsp` : (Value ignored) Remove the [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) (CSP) headers from original response.
- `_sgp_trimresheader` : (Value ignored) Remove all response headers except Content-Type/Length/Encoding/Range.
- `_sgp_insecure` : (Value ignored) Ignore any TLS cert error in http request.
- `_sgp_norf` : (Value ignored) Do not follow redirects.
- `_sgp_nocache` : (Value ignored) Add the no-cache headers to original response.
- `_sgp_debug` : (Value ignored) Debug mode.
- `_sgp_proxy=socks5://1.2.3.4:1080` : Set the proxy for the http request.
- `_sgp_timeout=5` : Set the timeout for the http request (seconds).
- `_sgp_method=GET` : Set the method for the http request. Default to `GET`.
- `_sgp_header_<any>=<value>` : Set the request header. E.g.: `_sgp_header_Authorization=Token%20abcdef` will set the "Authorization: Token abcdef" request header. If value is empty, will remove the target header from request.
- `_sgp_resheader_<any>=<value>` : Similar to `_sgp_header_`, but set or remove the response header.
- `_sgp_sub_<string>=<replacement>` : Response body substitutions. Similar to nginx [http_sub](https://nginx.org/en/docs/http/ngx_http_sub_module.html) module. See below "Response body substitutions" section.
- `_sgp_subr_<Regexp>=<replacement>` : Similar to `_spg_sub_*` but do regexp find and replacement.
- `_sgp_subb_<HexString>=<replacement>` : Similar to `_spg_sub_*` but do binary bytes find and replacement.
- `_sgp_subpath=<value>`: Array Value. Apply response substitutions only if target url path ends with this value. E.g. `.html`.
- `_sgp_subtype=<value>`: Array Value. Apply response substitutions only if target url original response has this content type. E.g. `txt`, `text/plain`. Use empty string to match original response which does not have a "Content-Type" header. Use `*` to accept all content types.
- `_sgp_forcesub` : (Value ignored) Force do response body substitutions on any MIME type response.
- `_sgp_cookie=<value>` : Set request cookie. Equivalent to `_sgp_header_cookie=<value>`.
- `_sgp_type=<value>` : Set the request content type. Similar to `_sgp_header_Content-Type=<value>`.
- `_sgp_restype=<value>` : Set the response content type. Similar to `_sgp_resheader_Content-Type=<value>`.
  - If `_sgp_method` is set to `POST` and `_sgp_body` is also set, the `_sgp_type` will have a default value `application/x-www-form-urlencoded`.
  - The `_sgp_type` and `_sgp_restype` parameters also accept file extension values like `txt` or `html`, in which case it will use the MIME type associated with the file extension ext; it's also the recommended way to set these two parameters.
  - If `_sgp_restype` is set to `*`, it will automatically guess the value from the suffix of current target url path, e.g. `https://example.com/foo.txt` will set response content-type to `text/plain`; if the url path ends with `/`, it will set response content type to `text/html`.
- `_sgp_body=<value>` : Set the request body (String only. Binary data is not supported).
- `_sgp_resbody=<value>` : Set the response body template.
- `_sgp_resbodytype=<value>` : The original response body type, e.g. `json`, `xml`, `yaml`, `toml`.
- `_sgp_fdheaders=<value>` : Array Value. Forward headers list. For every header in the list, if the http request to the "entrypoint url" itself contains that header, Simplegoproxy will set the request header to the same value when making http request to the "target url". E.g.: `_sgp_fdheaders=Referer,Origin`. By default some headers will ALWAYS be forwarded, even if not specified: `Range`, `If-*`. If a `_sgp_header_*` parameter is set, it will override the same name forwarded header. Some values have special meanings:
  - `*`: ALL request headers.
  - `%0A` (\n) : Supresses default forwarding headers and makes sure no headers would be forwarded.
  - `:method` : Forward the http request method. Use the incoming method to the entrypoint url as the one sent to the target url.
  - `:body` : Forward the http request body. Use the incoming body to the entrypoint url as the one sent to the target url.
- `_sgp_user=username:password` : Set the authentication username & password for request. It can also be directly set in target url via "https://user:password@example.com" syntax.
- `_sgp_impersonate=<value>` : Impersonate itself as Browser when sending http request. See below "Impersonate the Browser" section.
- `_sgp_sign=<value>` : The sign of request canonical url. See below "Request signing" section.
- `_sgp_keytype=<value>` : The sign key type. See below "Signing key type" section.
- `_sgp_scope=<value>` : Array Value. The scope of sign. See below "Scope signing" section.
- `_sgp_eid=<value>` : The encryption url id. See below "URL Encryption" section.
- `_sgp_epath` : (Value ignored) Enable plaintext relative url and normal query variables for encrypted url.
- `_sgp_status=<value>` : Force set http response status code sent back to client. E.g. `200`, `403`. Special values: `-1` - Use original http response code.
- `_sgp_auth=user:pass` : The auth username & password for request to the Simplegoproxy server. See below "Request authentication" section.
- `_sgp_authmode=1` : The request authentication mode. See below "Request authentication" section.
- `_sgp_respass=<value>` : The password to encrypt the response. See below "Response encrpytion" section.
- `_sgp_localsign=<value>` : The local scope url sign. See below "Response encrpytion" - "Local signing" section.
- `_sgp_encmode=4` : The response encryption mode, bitwise flags integer. See below "Response encrpytion" section.
- `_sgp_tplmode=1` : The response template mode, bitwise flags integer. See below "Response template" section.
- `_sgp_tplpath=<value>` : Array Value. Apply response template only if target url path ends with this value. E.g. `.gohtml`. Set to `*` to apply to any url.
- `_sgp_tpltype=<value>` : Array Value. Apply response template only if target url original response has this content type. E.g. `txt`, `text/plain`. Use empty string to match original response which does not have a "Content-Type" header. Use `*` to accept all content types.
- `_sgp_jstplpath=<value>` : Array Value. Use JavaScript template if target url path ends with this value. E.g. `.tpl.js`. Set to `*` to apply to any url.
- `_sgp_mutestatus=<value>` : Array Value. If the target url original response has this status code, "mute" this response (discard this reponse and sent a standard 404 not found page to client instead). Possible values:
  - `*` : All status codes except `200` and `206`.
  - `!xxx` : All non-xxx status codes. E.g. `!200`.
  - `xxx` : A specific status code. E.g. `404`.
- `_sgp_mutepath=<value>` : Array Value. If the target url path ends with this suffix, do not fetch it and sent a standard 404 not found page to client instead. The `*` means any path that ends with `/`, or the last segment of path has a file extension (containing `.` char).
- `_sgp_mutetype=<value>` : Array Value. If the target url original response has this content type, "mute" this response. Possible values:
  - empty string: The empty or non-present "Content-Type".
  - `*` : All content types except `text/html` and `text/plain`.
  - `xxx` or `xxx/xxx` : Specific content type. E.g. `txt`, `text/plain`.
  - `!xxx` : All content types except this specific type. E.g. `!html`.
- `_sgp_indexfile=<value>` : If this parameter is set and the current target url ends with `/`, Simplegoproxy will append this parameter to the end of target url before fetching it. E.g. `index.html`.
- `_sgp_md2html` : (Value ignored) Render markdown to html. If this parameter is set and the response has a content type of `text/markdown`, Simplegoproxy will convert the response body from markdown to html and set `Content-Type: text/html` response header.
- `_sgp_mdpath` : Array Value. If the target url path ends with this suffix, do markdown-html conversion.
- `_sgp_salt=<value>` : The response encryption key salt. See below "Response encryption" section.
- `_sgp_publickey=<value>` : The response encryption ECDH client pulic key (hex string). See below "Response encryption" section.
- `_sgp_referer=<value>` : Array Value. Set the allowed referer of request to the entrypoint url. See below "Referer restrictions" section.
- `_sgp_origin=<value>` : Array Value. Set the allowed origin of request to the entrypoint url. See below "Origin restrictions" section.
- `_sgp_validbefore=<value>`, `_sgp_validafter=<value>` : If set, the entrypoint url can only be used before or after this time accordingly. Value can be any of below time formats: `2006-01-02`, `2006-01-02T15:04:05` `2006-01-02T15:04:05-07:00`, `2006-01-02T15:04:05Z`. All but the last format are parsed in local timezone. The last one are parsed as UTC time. Note to enforce these restrictions, "Request signing" must be enabled.

Modification paramaters are set in Query Variables. All `_sgp_*` parameters are stripped from the target url when Simplegoproxy fetch it. E.g.: the `http://localhost:8380/https://ipcfg.co/json?abc=1&_sgp_cors` entry will actually fetch the `https://ipcfg.co/json?abc=1` target url.

All "escapable" characters in paramater name & value should be escaped in '%XX' format. (In general, the "escapable" means JavaScript's `encodeURIComponent` function return a escaped string for the char)

## Features

### Modification parameters fronting

Instead of using Query Variables to set modification parameters, You can also put them in the "path", after the root path but before the target url. E.g.:

```
http://localhost:8380/_sgp_cors/https://ipcfg.co/json
```

### Response body substitutions

Response body substitutions modify the original http response returned by the target url server, replacing one certain string (needle) with another (replacement). It's somewhat similar to nginx [http_sub](https://nginx.org/en/docs/http/ngx_http_sub_module.html) module.

To do response body substitutions, use any of the following parameters to set the find-and-replace rule(s). These parameters can be specified multiple times. Note both the needle and replacement part of the string should be url encoded.

- `_sgp_sub_<string>=<replacement>` : Do basic string find and replacement. E.g. `_sgp_sub_org=ORG`: `org` => `ORG`.
- `_sgp_subr_<Regexp>=<replacement>` : Do regexp find and replacement. E.g. `_sgp_subr_No.%5Cs*(%5Cd%2B)=no-$1`: `No.\s*(\d+)` => `no-$1`, it will search for patterns like `No. 123` and replace it with `no-123`.
- `_sgp_subb_<HexString>=<replacement>` : Do binary find and replacement. Use hex string format. E.g. `_sgp_subb_aabb=ccdd`: `aa bb` => `cc dd`.

The response body substitutions are only applied when certain conditions meet. Change default behavior by setting the follow parameters:

- `_sgp_subpath=<value>`: Array Value. Apply substitutions only if target url path ends with this value. E.g. `.html`. If none is set, url path suffix check is skipped.
- `_sgp_subtype=<value>`: Array Value. Apply substitutions only if target url original response has this [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types) ("Content-Type"). E.g. `txt`, `text/plain`. Set to `*` to accept all content-types. If none is set, default behavior is to apply substitutions if the original response has a textual content type, which could be any one of the following: `text/*`, `application/json`, `application/xml`, `application/yaml`, `application/toml`, `application/atom+xml`, `application/x-sh`.
- `_sgp_forcesub=1`: Force do substitutions on any response, no matter of it's url path suffix or content type.

### Impersonate the Browser

Simplegoproxy can impersonate itself as Browser when sending http request to target url. It's similar to what [curl-impersonate](https://github.com/lwthiker/curl-impersonate) does. To enable this, set the `_sgp_impersonate` modification parameter to target browser name. E.g.:

```
http://localhost:8380/_sgp_impersonate=chrome120/https://ipcfg.co/json
```

Simplegoproxy will print the list of supported targets when starting. Currently supported impersonates:

- `chrome120` : Chrome 120 on Windows 11 x64 en-US
- `firefox121` : Firefox 121 on Windows 11 x64 en-US

### Response template

if `_sgp_resbody` parameter is set, Simplegoproxy use it as a [Go template](https://pkg.go.dev/text/template) for renderring response body. E.g.:

```
{{.Res.Status}}

{{.Res.Body}}
```

#### The template context

Some context variables are available in template:

- `Params` : The all `_sgp_*` parameters of current request (param names don't have `_sgp_` prefix). type: [url.Values](https://pkg.go.dev/net/url#Values).
- `Res` : The original http response sent by the target url server.
  - `Res.Status` : http response status code, e.g. `200`. type: `int`.
  - `Res.Header`: http response header. type: [http.Header](https://pkg.go.dev/net/http#Header).
  - `Res.Body` : http response body. type: `string`.
  - `Res.Data` : http response body parsed data object. type: `any`.
- `Req` : The http request sent to the target url server.
  - `Req.URL` : http request url. type: [url.URL](https://pkg.go.dev/net/url#URL).
  - `Req.Header` : http request header.
- `SrcReq` : The original http request sent to the Simplegoproxy server by client.
  - `SrcReq.URL` : http request url.
  - `SrcReq.Header` : http request header.
  - `SrcReq.RemoteAddr` : http request source addr, e.g. `192.168.1.1:56789`.
- `Err` : Error encountered, if any.
- `Ctx` : An empty `map[string]any` container ready for use.
- `Now` : The now server time. type: [time.Time](https://pkg.go.dev/time#Time).

Notes:

- The response template is only applied when certain conditions meet. Change default behavior by setting the follow parameters:
  - `_sgp_tplpath=<value>`: Array Value. Apply response template only if target url path ends with this value. E.g. `.gohtml`. If none is set, url path suffix check is skipped.
  - `_sgp_tpltype=<value>`: Array Value. Apply response template only if target url original response has this content type. E.g. `txt`, `text/plain`. Set to `*` to accept all content-types. If none is set, default behavior is to apply template if the original response has a textual "Content-Type".
- The `res.data` is by default parsed according to original http response's content-type header. You can forcibly specify the type using `_sgp_resbodytype` parameter (json / yaml / xml / toml).
- The status of rendered response is `200` by default, use `_sgp_status` parameter to override it.
- The "content-type" of renderred response is `text/html` by default, use `_sgp_restype` parameter to override it.
- If `_sgp_restype` is set to "html", the template renderring will use Go [html/template](https://pkg.go.dev/html/template); otherwise it will use Go [text/template](https://pkg.go.dev/text/template).
- Some special functions can be used in templates to change the response status code and / or header. These functions always return empty string.
  - `set_status(status)` : Set response status code.
  - `set_header(key, value)` : Set a response header. If value is empty string, delete the header instead.
  - `clear_header()` : Clear all response header except `Content-*`.
  - `set_body(body)` : Instead of using template renderring output, use `body` as the response body. `body` could be any type of `string`, `[]byte`, `io.ReadCloser` or `io.Reader`.

If current entrypoint url is signed, some more pre-defined functions are available in template:

- `fetch(options...)` : Do a arbitary http request, return `{Err, Status, Header, RawBody, Body, Data}`.
  - The `options` args is an string array which elements could be any of:
    - http method: e.g. `GET`.
    - http header: e.g. `Content-Type: text/plain`.
    - http request body: starts with `@`, e.g. `@a=1&b=2`.
    - `NOBODY` : special flag, do not read and parse response body.
    - `INSECURE` : special flag, disable request TLS cert verification.
    - A string starts with `https://` or `http://` : the target url to fetch.
  - `Body`, `Data`: The response body string and parsed data object. Set when `NOBODY` flag is not present.
  - `RawBody`: The raw response body (`io.ReadCloser`). Set when `NOBODY` flag is present.
- `system(cmdline)` : Execute a cmdline and return exit code. If stdout is needed, use `exec()` instead.
- `exec(options...)` : Execute a cmdline and return `{Err, Out}`.
  - The `options` args is an string array which elements could be any of:
    - `?COMBINED` : A special flag to make outout the combined stdout & stderr, instead of stdout only.
    - cmdline string.
  - `Out`: The outout string.
- `read(input)` : Read a `io.ReadCloser` or `io.Reader`, return all of it's contents as `[]byte`.
- `unmarshal(typ, data)` : Parse data (string or []byte) to object according to type. `typ` could be file ext (e.g. `txt`) or mediatype (e.g. `text/plain`).
- `marshal(typ, data)` : Serialize data to string.
- `eval(input)` : Evaluate an JavaScript snippet using [goja](https://github.com/dop251/goja) JavaScript engine, return result.
  - The above context variables are also available in JavaScript runtime.
  - `console` functions (e.g. `console.log`) are available in JavaScript runtime, which will output to stderr of Simplegoproxy process.
  - Some above functions (e.g. `fetch`, `exec`, `set_status`...) are also available in JavaScript runtime. Note that the above `fetch` function is available as `fetchUrl` in JavaScript runtime, to distinguish it from ECMA [fetch](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API). For list of all available functions, see [tpl/js.go](https://github.com/sagan/simplegoproxy/blob/master/tpl/js.go).
  - To interchange data between normal template runtime and JavaScript runtime, use `Ctx` context variable.
  - If `eval` returns a Promise, the resolved value will be used as result.
  - Other template functions (like `set_body`) also support Promise generated by JavaScript runtime as arg.
  - All eval blocks of the template share the same JavaScript runtime.
- ....
- For full func list, see [tpl/tpl.go](https://github.com/sagan/simplegoproxy/blob/master/tpl/tpl.go).
- Plus with all functions from Go [Sprig](https://github.com/Masterminds/sprig) library.

#### Template mode

The `_sgp_tplmode` (template mode, default to 0) is a bitwise flags integer parameter that can control several response template behaviors:

- bit 0 (`& 1`): Always uses text template, never uses html template..
- bit 1 (`& 2`) : Use target url original response body as template. In this case, the `_sgp_resbody` is not mandatory required; it will instead serve as `Res.Body` context variable.
- bit 2 (`& 4`) : Do not read target url original response body prior renderring. The `Res.Body` will not be set; Instead, the `Res.RawBody` context variable will be set to the raw body `io.ReadCloser`.
- bit 3 (`& 8`) : Always do response template no matter of target url path suffix or response content type.
- bit 3 (`& 16`) : Keep the content-type of original response unchanged.

#### Template examples

Basic example:

```
{{- set_status 404 -}}
{{- set_header "Content-Type" "text/html" -}}

{{with $x := fetch "https://ipinfo.io" }}
raw body: {{ $x.Body }}
city: {{ $x.Data.city }}
{{end}}
```

A more complex template using JavaScript (eval) along with other functions:

```javascript
// Use comment tricks to make the whole template valid JavaScript
// However, some literals like ` or double left / right bracelet can not be used in JavaScript codes.

/*
{{ $_ := fetch "https://ipinfo.io/json" | set .Ctx "res" }}
{{ $_ := exec "curl --version" | set .Ctx "res2" }}
*/

// {{ eval `
async function output() {
  return Ctx.res.Data.ip + " " + Ctx.res.Data.city + "\n" + Ctx.res2.Out;
}
Ctx.body = output();
// ` }}

/*
{{ set_body .Ctx.body }}
*/
```

#### JavaScript template

If `_sgp_jstplpath` parameter is set and current url path ends with any `_sgp_jstplpath` value (e.g. `.tpl.js`), the whole template is intepreted as JavaScript.

Example JavaScript template:

```js
function main() {
  let res = fetch("https://ipinfo.io/json"); // It's different from ECMA fetch!
  let res2 = exec("curl --version");
  return `---
Http
Status: ${res.Status}
Body: ${res.Body}

Curl
Output: ${res2.Out}
---`;
}

main();
```

### Admin UI

Simplegoproxy provides a http admin UI at `<rootpath>` + `/admin/` path by default, e.g. `http://localhost:8380/admin/`, use `-adminpath` flag to change the admin UI path. The admin UI allow users to generate entrypoint url for a target url and view history records of generated entrypoint urls. All data are stored in the browser local storage.

### "data:" urls

Simplegoproxy supports `data:` urls ([Data URLs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URLs)), which will use the provided contents directly as the response body.

E.g.

```
http://localhost:8380/data:,Hello%2C%20World%21

http://localhost:8380/data:text/html;base64,SGVsbG8sIFdvcmxkIQ==
```

Both of above entrypoint urls will output "Hello, World!". The later one will also set the `Content-Type: text/html` response header.

### `unix://`, `file://`, `rclone://`, `curl+*//`, `exec://` urls

By default, Simplegoproxy only supports `http(s)` and `data` scheme urls.

If `-enable-unix`, `-enable-file`, `-enable-rclone` or `-enable-exec` flag is set, Simplegoproxy will support some additional schemes of urls respectively.

- `-enable-unix` : Make Simplegoproxy supports URLs of http(s) over unix domain socket in local file system. Target url example: `unix://path/to/socket:http://server/path`. Use `:` to split http resource url with the unix domain socket file path.
- `-enable-file` : Make Simplegoproxy supports `file://` ([File URI scheme](https://en.wikipedia.org/wiki/File_URI_scheme)) urls, which reference to local file system files. Directory Index is also supported. Target url examples:
  - `file:///root/foo.txt`: The `/root/foo.txt` file.
  - `file:///D:/foo.txt` : The `D:\foo.txt` file. (Windows)
  - `file://server/share/foo.txt`: The `\\server\share\foo.txt` file. (Windows UNC path)
  - `file:////server/share/foo.txt` : Same as above, another form of UNC path.
- `-enable-rclone` : Make Simplegoproxy supports `rclone://` urls, which reference to a file in [rclone](https://github.com/rclone/rclone) remote. Target url example: `rclone://remote/path/to/file.txt`, which will get the contents of `remote:path/to/file.txt` file using rclone. It lookups rclone from PATH and use default rclone config file location (`~/.config/rclone.conf`). To use other locations, use `-rclone-binary` and `-rclone-config` flags.
  - For a regular file, it will run `rclone cat remote:path` to get file contents and output it to client.
  - For a dir, it will run `rclone lsjson remote:path` to get file list of the dir, and output the Directory Index page to client.
- `-enable-curl` : Make Simplegoproxy supports `curl+*://` urls, which will spawn a [curl](https://curl.se/docs/manpage.html) process to fetch the actual url. Target url example: `curl+https://ipinfo.io`. It lookups curl from PATH. To use other location, use `-curl-binary` flag.
- `-enable-exec` : Make Simplegoproxy supports `exec://` urls, which spawn a child process and return it's stdout to client. Target url example: `exec://curl?args=-i+ipinfo.io`, which will execute `curl -i ipinfo.io`. You can also specify the full path of executable file use the same format as `file://` scheme url.
  - By default, If the spawned process started successfully, it sends `200` status code immediately to client and then piping the stdout of spawned process to response body; if the process finally exits with non-zero, there is no way to notify it to client.
  - If `_sgp_timeout=10` pamameter is set, it will wait for at most this time (seconds) before beginning sending the stdout of process to client. If the process exitted within this time range with a non-zero exit code, it will send `500` status to client.
  - By default the response's Content-Type is `text/plain`. Use `_sgp_restype` parameter or `type` normal query variable to override it.

For `rclone://`, `curl+*//`, `exec://` urls, if `_sgp_debug` modification parameter is set, it will output the combined stdout and stderr of spawned child process, instead of stdout only.

Note some `_sgp_*` modification parameters don't work with most of above schemes urls, obviously the ones that modify http request.

### URL Aliases

Simplegoproxy supports url "alias" using `-alias <prefix>=<path>` flag. It can be set multiple times. The `<prefix>` part is the path of the entrypoint url, it doesn't need to start with the "rootpath". The `<path>` part consists of the fronting modification parameters and the prefix of target url. E.g.:

```
simplegoproxy -alias "/test/=/_sgp_cors=1/https://ipinfo.io/"
```

Then the following "alias" entrypoint urls will be equalvalent to non-alias ones:

- `http://localhost:8380/test/` => `http://localhost:8380/_sgp_cors=1/https://ipinfo.io/`.
- `http://localhost:8380/test/ip` => `http://localhost:8380/_sgp_cors=1/https://ipinfo.io/ip`.

Notes:

- The "alias" entrypoint urls do not require explicit signing and always treated as already signed (That's say, `_sgp_sign` parameter is not required).
- In an "alias" url, all modification parameters must be inside the alias `<prefix>` part and can not exist in the URL query variable. The below parameters are exceptions: `_sgp_salt`, they can still exist in query variables of an "alias" url.

## Security features

### Set the rootpath

If your Simplegoproxy instance will be publicly accessible, you can set the "rootpath" flag to a "confidential" value other than the default "/". It acts like a password.

E.g.: If rootpath is set to "/abc/", then the entrypoint url should be like `http://localhost:8380/abc/https://ipcfg.co/json`.

### Request signing

If "key" flag is set, "request signing" will be enabled. It's the core security mechanism of Simplegoproxy. When request signing is enabled, all requests to Simplegoproxy must be signed via HMAC-SHA-256 using the key. The message being signed is the "canonical url" of the request. The result MAC (message authentication code) must be provided in `_sgp_sign` parameter of the request.

The "canonical url" is the target url with all `_sgp_*` modification parameters (excluding `_sgp_sign` and `_sgp_keytype`) in query values. All query values sorted by key.

It's recommended to use the "Admin UI" to sign a target url and get the signed entrypoint url.

You can also calculate the sign of a target url using CLI by running `simplegoproxy` with `-sign` flag. E.g.:

```
#simplegoproxy -sign -key abc "https://ipinfo.io/ip?_sgp_cors"
https://ipinfo.io/ip?_sgp_cors=  e9ccc14d94cd952d08bef094d9037c26b624a8bf18e6dc6c223d76224d4196ef
```

It outputs the canonical url of the request along with calculated sign.

Then use the following entrypoint url :

```
http://localhost:8380/https://ipinfo.io/ip?_sgp_cors&_sgp_sign=e9ccc14d94cd952d08bef094d9037c26b624a8bf18e6dc6c223d76224d4196ef

# or
http://localhost:8380/_sgp_cors&_sgp_sign=e9ccc14d94cd952d08bef094d9037c26b624a8bf18e6dc6c223d76224d4196ef/https://ipinfo.io/ip

# or
http://localhost:8380/_sgp_sign=e9ccc14d94cd952d08bef094d9037c26b624a8bf18e6dc6c223d76224d4196ef/https://ipinfo.io/ip?_sgp_cors
```

If you pass a `-publicurl http://localhost:8380` flag when invoking the above command, it outputs the final entry url diretly:

```
simplegoproxy -sign -key abc -publicurl "http://localhost:8380" "https://ipinfo.io/ip?_sgp_cors"
https://ipinfo.io/ip?_sgp_cors=  http://localhost:8380/_sgp_sign=e9ccc14d94cd952d08bef094d9037c26b624a8bf18e6dc6c223d76224d4196ef/https://ipinfo.io/ip?_sgp_cors=
```

Notes:

- It's possible to make specific urls do not require signing, see below "Open scopes" section.
- If a request is not signed, some features will NOT work, e.g. env substitutions, pre-defined response template functions.
- Most of other security mechanisms of Simplegoproxy require request signing to be enabled, or they will not work, e.g. URL encryption, request authentication, response encryption. It's highly recommanded to enable request signing in production environment.
- Requests to the "alies" URLs (See above "URL Aliases" section) do not need signing and act as if already signed.

### Admin UI Authorization

If request signing is enabled (key is set), the admin UI will require [http authentication](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication):

- Username: Default is `root`. Can be changed by `-user string` flag.
- Password: Default use "key" flag as password. Use `-pass string` flag to set standalone password.
- Authentication type: Default is "digest auth". Use `-basic-auth` flag to change to "basic auth" (less secure but much more easy to use programmatically).

### Env substitutions

If the entrypoint url is signed, all `__SGPENV_**__` style substrings in modification parameter value will be replaced with the value of the corresponding `**` environment variable, if it exists, when sending request to the target url. E.g. `__SGPENV_PATH__` will be replaced by `PATH` env value.

If current url is not scope-signed (no `_sgp_scope` parameter is set), Env substitutions will also apply to the normal query variable values.

The substitutions occur after the url sign verification.

### Signing key type

It's possible to provide a optional "key type" value whening signing a url. The "key type" value will be appended to the "key" to derive the effective actual HMAC key.

To sign a url, set a `-keytype string` flag:

```
simplegoproxy -key abc -keytype one -sign -publicurl http://localhost:8380 ipinfo.io
```

Output:

```
https://ipinfo.io/  http://localhost:8380/_sgp_keytype=one&_sgp_sign=94bb9904ac8975e1dc3617ca49a9ed4481d7db6626859978dddcd29c3999d3f0/https://ipinfo.io/
```

The generated entrypoint url will have the `_sgp_keytype` parameter with same value.

The design purpose of "key type" is that, you can selectively "revoke" the entrypoint urls of some "key type(s)" without invalidating other urls. To do this, set the `-keytypebl string` flag to the comma-separated blacklist of revoked key types:

```
simplegoproxy -key abc -keytypebl one,two,three
```

Without "key type", a signed url can only be revoked by changing the "key", which will invalidate all previous generated entrypoint urls.

### Scope signing

If any none-empty `_sgp_scope` parameter is provided, the sign is calculated against the whole scope, which is a [Chrome extension style match pattern](https://developer.chrome.com/docs/extensions/develop/concepts/match-patterns), instead of against the single target url.

E.g.:

```
localhost:8380/_sgp_scope=https%3A%2F%2F%2A%2F%2A/ipinfo.io/ip
```

Here, the `_sgp_scope` is `https://*/*` , which matches all https URLs. The payload ("canonical target url") of scope signing is a `?` character plus all `_sgp_` parameters sorted by key. To calculate it:

```
simplegoproxy -sign -key abc "?_sgp_scope=https://*/\_"
edb3aaafe81cc42ea94a862bb5b77b4876d39ab3748410716bc9d7041e64c715 ?_sgp_scope=https%3A%2F%2F%2A%2F%2A
```

Then use the following entrypoint url:

```
curl -i "localhost:8380/_sgp_sign=edb3aaafe81cc42ea94a862bb5b77b4876d39ab3748410716bc9d7041e64c715&_sgp_scope=https%3A%2F%2F%2A%2F%2A/ipinfo.io/ip"
```

Notes:

- The `_sgp_scope` parameter can be set multiple times. The sign can be used to access any target URL which matches with at least one provided scope.
- A `*` scheme in scope parameter means "http" or "https". E.g. the `*://*/*` scope matches with all "http://" or "https://" urls. If you want to target other schemes like "file" ("file://" url) as well, you must put it in explicitly.

### Open scopes

When request signing is used, you can define some "open scopes" using `-open-scope string` flags. E.g.:

```
-open-scope "http://example.com/*"
```

This flag can be set multiple times. Target urls of these scopes do not require (enforce) signing. However, env substitutions do not work if a such scope url is not signed. The `-open-normal` flag can be used to make all `http`, `https` and `data` scheme urls do not require signing.

### URL encryption

Instead of putting the plain text target url inside the entrypoint url. If request signing is enabled, Simplegoproxy also accepts the "encrypted form entrypoint url" in which the target url exists as cipher text.

To get the encrypted form entrypoint url, use the `-encrypt` flag with `-sign` when signing an url using CLI; Or check the "Encrypt" checkbox in Admin UI.

Note the "Modification parameters fronting" does not work with URL encryption -- the whole target url with all query parameters will be encrypted. The encrypted entrypoint url contains only one path segment, e.g.: `http://localhost:8380/abcdefghijklmnopqrstuvwxyz`.

It's possible to prepand a fixed `eid` (encrypted url id) string to the beginning of the generated url to help you identify a encrypted url. To do it, input the "eid" in admin UI or use the `-eid <value>` CLI flag. The encrypted entrypoint url will have format `http://localhost:8380/myeid_abcdefghijklmnopqrstuvwxyz`. Only `[_a-zA-Z0-9]` (regexp) charasters is allowed in `eid`.

The target urls are encrypted using "key" flag value as the cryptographic key. If you change the key, all previously generated entrypoint urls will be inaccessible.

If the `_sgp_epath` parameter is set, the encrypted url can also take a suffix of "relative url" and / or normal query variables. For example, if `http://localhost:8380/aabbccddeeff` is the encrypted entrypoint url of `http://example.com/test/`, then `http://localhost:8380/aabbccddeeff/children/path?foo=bar` can be used to access `http://example.com/test/children/path?foo=bar` target url (here the "relative url" is "/path"). Note you also need to set the `_sgp_scope` (scope signing) parameter to sign the whole scope target urls, or it will not work.

### Request authentication

If the `_sgp_auth=uass:pass` parameter is set, request authentication is enabled. The request to the entrypoint url will require http access authentication using specified username & password. Note only the encrpyted form entrypoint url can be used in this case, unless current request is accessed via a "alias" url.

By default it uses [basic access authentication](https://en.wikipedia.org/wiki/Basic_access_authentication). If `_sgp_authmode` (bitwise flags integer) parameter is set to `1`, it will use [digest access authentication](https://en.wikipedia.org/wiki/Digest_access_authentication).

### Response encryption

If the `_sgp_respass=<value>` parameter is set, response encrpytion will be enabled. Simplegoproxy will encrypt the response body sent back to client using the parameter's value as password. The encryption uses AES256-GCM with the cryptographic key derived from password via [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) + SHA-256 of by default one (1) iterations and no salt. The response body sent back to client is the base64 string of `iv (12 bytes) + ciphertext`. Note only the encrpyted form entrypoint url can be used in this case, unless current request is accessed via a "alias" url.

By default, the http response will always has `200` status with only three http headers: `Content-Type: text/plain` and `Content-Length`; Along with the `X-Encryption-Meta` header, which is the encrypted base64 string of the json object `{status, header, body_length, body_sha256, date, encrypted_url, request_query, source_addr}`:

- `status` : (number) The original http response status code. E.g. `200`.
- `header` : (object) The original http response header.
- `body_length` : (number) The body (prior base64) length.
- `body_sha256` : (string) The sha256 of (encrypted) response body.
- `date` : (string) The server date time when response is sent back to client. E.g. `2006-01-02T15:04:05Z`.
- `encrpyted_url` : (string) The original encrypted url that Simplegoproxy server received.
- `request_query` : (string) The original http request query string that Simplegoproxy server received.
- `source_addr` : (string) The source addr of original http request that Simplegoproxy server received. E.g. `192.168.1.1:56789`.

#### Encryption mode & parameters

The `_sgp_encmode` (encryption mode, default to 0) is a bitwise flags integer parameter that can control several encryption behaviors:

- bit 0 (`& 1`): Make the response body be binary data instead of base64 string.
- bit 1 (`& 2`) : Make only response body be encrypted: response header not protected.
- bit 2 (`& 4`) : Make the response body be encrypted data of the a JSON object which has the same structure as above `X-Encryption-Meta` header (without `body_length` and `body_sha256`), plus two string type fields: `body`, `body_encoding`. The `body_encoding` indicates the encoding method of `body`, possibly values: empty string, `base64`.
- bit 3 (`& 8`) : Used with bit 2 set. Force json "body" field to be original http rersonse string.
- bit 4 (`& 16`) : Used with bit 2 set. Force json "body" field to be base64 string of original http rersonse.
- bit 5 (`& 32`) : Enable local signing. (See below)
- bit 6 (`& 64`) : Only do local signing, no encryption. (See below)

Additional encryption parameters:

- `_sgp_passiter` : (Default is 1) The PBKDF2 iteration count.
- `_sgp_salt` : (Default is empty) The salt in PBKDF2 key derivation. It's recommended to set a cryptographically secure random string as salt for each request.

#### Public key encryption mode

Besides above "normal" encryption mode, if the request to the server contains `_sgp_publickey` paramter, response encryption will use a "public key" encryption mode that derives AES-256-GCM key from not only the password & salt, but also the [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) ([Curve25519](https://en.wikipedia.org/wiki/Curve25519) / X25519) key exchange of a client provided public key and a server generated request scope ephermal private key. This mode is more complicated but provides [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy). To use this mode, follow the below procedures:

1. Client generates a random X25519 private key & public key.
2. Client sends the request to Simplegoproxy server via encrypted form entrypoint url, puts it's public key (hex string) in `_sgp_publickey` parameter of the request.
3. Server generates it's own X25519 private key & public key, derives the AES-256 key (32 bytes) from password and ECDH. The generated keys (private key & public key & AES-256 key) is ephemeral and will be destroyed after current request is handled.
4. Server puts it's own public key in `X-Encryption-Publickey` header (base64 string) and sends the AES-256-GCM encrypted data in http body.
5. Client derives the AES-256 key from password and ECDH, uses it to decrypt the data.

To derive the AES-256 key:

1. Generate the 32 bytes `key` from password & salt(`_sgp_salt`) & iter(`_sgp_passiter`) using PBKDF2 - SHA-256 (the same as "normal" response encryption mode).
2. Do X25519 ECDH using self (client) private key and remote (server) public key to derive the share `secret` (also 32 bytes length).
3. Derive the 32 bytes `key1` from `secret` using PBKDF2 - SHA-256 with salt = empty, iter = 1.
4. Apply `key = key ^ key1` (XOR) to derive the final effective symmetric AES-256 key.

#### Local signing

The "Public key encryption mode" can provide forward secrecy. However, it cann't prevent [replay attacks](https://en.wikipedia.org/wiki/Replay_attack). To prevent replay attacks, "Response encryption" supports an "local signing" mode which can be enabled by setting `bit 5 (& 32)` flag of `_sgp_encmode`.

In this mode, every request to the encrypted entrypoint url must has some additional parameters:

- `_sgp_nonce`: The [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) generated by client. Must be in the `2006-01-02_15-04-05XXX` format, the prefix is the current time string (UTC) and the suffix should be a cryptographically secure random string. Server wil reject the request if the time in nonce is too early compared to server time, or the nonce has already be used once recently before.
- `_sgp_localsign` : The hex string format HMAC-SHA-256 sign of "localsign_url" using `_sgp_respass` as the key.

The "localsign_url" is the "relative url" with prefix "/" stripped (could be empty) plus "?" plus all query variables sort by key (except `_sgp_localsign`). For example, if the encrypted entrypoint url is `http://localhost:8380/aabbccddeeff` :

- `http://localhost:8380/aabbccddeeff?_sgp_nonce=...&_sgp_localsign=...` : The "localsign_url" is `?_sgp_nonce=...`.
- `http://localhost:8380/aabbccddeeff/foo?_sgp_nonce=...&_sgp_publickey=...&_sgp_localsign=...` : The "localsign_url" is `foo?_sgp_nonce=...&_sgp_publickey=...`.

Notes:

- If the entrypoint url is an "alias" url, the relative url is the part of url path provided by the user.
- If the `bit 6 (& 64)` flag of `_sgp_encmode` is set, it only requires request signed by the above local signing procedure, but the response is not encrypted at all.

#### Encryption best practive

To archive the best level of security, combine the "Public key encryption mode" with "Local signing".

Use only "public key encryption mode" without "Local signing" can not reliably provide forward secrecy, as the attacker can actively send a request without "pubkey" to server and save the opaque encrypted response for future use.

#### How to decrypt

This is a basic JavaScript (Browser & Node.js) example snippet to decrypt the encrypted response ("normal" encryption mode).

```javascript
/**
 * Decrypt the encrypted text sent by Simplegoproxy. Works in browser and node.js.
 * @param string ciphertext base64 encoded ciphertext(with iv as prefix)
 * @param string password
 * @return Promise<string> plaintext
 */
async function aesGcmDecrypt(ciphertext, password, salt = "", iter = 1) {
  const keymaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: iter,
      hash: "SHA-256",
    },
    keymaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  const cipherdata = Uint8Array.from(atob(ciphertext), (m) => m.codePointAt(0));
  const alg = { name: "AES-GCM", iv: cipherdata.slice(0, 12) };
  const plaindata = await crypto.subtle.decrypt(alg, key, cipherdata.slice(12));
  return new TextDecoder().decode(plaindata);
}
```

For example of more complicated usages like do local signing or decrypting "public key encryption mode" response, see [docs/decrypt.js](https://github.com/sagan/simplegoproxy/blob/master/docs/decrypt.js).

### Referer restrictions

If any `_sgp_referer` parameter is provided. Simplegoproxy will validate the `Referer` header of the request to the entrypoint url and only allow theses requests which referer match with at lease one provided `_sgp_referer` value.

The format of `_sgp_referer` should be a Chrome extension style match pattern (same as `_sgp_scope`). Additionaly, an empty value matches with the "Direct" request, in which case no `Referer` header is present.

Referer restrictions works even if request signing is not enabled.

### Origin restrictions

It works in the same way as the above "Referer restrictions" feature except that the parameter name is `_sgp_origin` and is verified against the `Origin` request header.

### Error Suppressions and Logging

By default, when Simplegoproxy web server encounters an error handling a request (e.g. signing verification failed), it displays the error to the client. If `-supress-error` flag is set, it will supress the error display, always sending a standard "404 Not Found" page to client if any error happens.

The Error Suppressions is forcibly enabled if current request is accessed via encrpyted form entrypoint url.

Also, by default Simplegoproxy does not log incoming requests and / or errors. To do the logging, set the `-log` flag, the log will outputted to stdout.
