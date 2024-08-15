# simplegoproxy

Simplegoproxy is a http / API proxy that can, and is designed and intended to be used to modify the http request headers, response headers and / or response body on the fly, based on custom rules per request, and then return the modified response to the user.

Simply put, Simplegoproxy generates an "entrypoint url", which can be accessed (GET) to make an arbitrary http request to the "target url" (All aspects of the Request or Response can be set or modified), and returns the final result (modified Response) to the user.

Use cases:

- Remove CORS restrictions.
- Add "Authorization" or other headers to the request.
- Apply string replacements on the response body.

## Run

Simplegoproxy is written in Go and published as a single executable file which requires no mandatory argument.

You can also run it using Docker:

```
docker run --name sgp -p 3000:3000 -d \
  ghcr.io/sagan/simplegoproxy
```

Command-line flag arguments:

```
  -cors
        Set "Access-Control-Allow-Origin: *" header for admin API
  -curl-binary string
        Curl binary path (default "curl")
  -enable-all
        Enable all schemes url: unix & file & rclone & curl & exec
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
  -key string
        The sign key. If set, all requests must be signed using HMAC(key, 'sha-256', payload=url), providing calculated MAC (hex string) in _sgp_sign
  -keytype string
        The sign keytype. Used with "-sign"
  -keytypebl string
        Comma-separated list of blacklisted keytypes
  -log
        Log every request urls
  -pass string
        Password of admin UI. If not set, the "key" will be used
  -port int
        Http listening port (default 3000)
  -prefix string
        Prefix of settings in query parameters (default "_sgp_")
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
  -user string
        Username of admin UI (Admin UI is available at "/admin" path) (default "root")
```

All arguments are optional, and can also be set by environment variable. The environment variable name is the flag name in uppercase and replacing `-` with `_`. E.g.: `port` flag can be set using `PORT` env; `enable-file` flag can be set using `ENABLE_FILE` env. To set a boolean (toggle) flag, use `true` of `false` env value.

## Usage

Append the target url to the root path to generate the "entrypoint url". E.g.: (Assume Simplegoproxy is started with the default "/' root path):

```
curl -i "localhost:3000/https://ipcfg.co/json"

# The scheme:// part of target url can be omitted, in which case "https://" is assumed
curl -i "localhost:3000/ipcfg.co/json"
```

The "entrypoint url" accepts GET requests only. By default it will just fetch the "target url" and return the original response, without any modification. Add specic query parameters to set the modification rules. E.g.:

```
curl -i "localhost:3000/https://ipcfg.co/json?_sgp_cors"
```

The `_sgp_cors` modification parameter indicates Simplegoproxy to modify the original response headers to set the CORS-allow-all headers:

```
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, OPTIONS
Access-Control-Allow-Origin: *
```

## Modification parameters

All modification paramaters has the `_sgp_` prefix by default, which can be changed via `-prefix` command-line argument.

- `_sgp_cors` : (Value ignored) Add the CORS-allow-all headers to original response.
- `_sgp_nocsp` : (Value ignored) Remove the [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) (CSP) headers from original response.
- `_sgp_insecure` : (Value ignored) Ignore any TLS cert error in http request.
- `_sgp_norf` : (Value ignored) Do not follow redirects.
- `_sgp_nocache` : (Value ignored) Add the no-cache headers to original response.
- `_sgp_debug` : (Value ignored) Debug mode.
- `_sgp_proxy=socks5://1.2.3.4:1080` : Set the proxy for the http request.
- `_sgp_timeout=5` : Set the timeout for the http request (seconds).
- `_sgp_method=GET` : Set the method for the http request. Default to `GET`.
- `_sgp_header_<any>=<value>` : Set the request header. E.g.: `_sgp_header_Authorization=Token%20abcdef` will set the "Authorization: Token abcdef" request header. If value is empty, will remove the target header from request.
- `_sgp_resheader_<any>=<value>` : Similar to `_sgp_header_`, but set or remove the response header.
- `_sgp_sub_<string>=<replacement>` : Similar to nginx [http_sub](https://nginx.org/en/docs/http/ngx_http_sub_module.html) module, modifiy the response by replacing one specified string by another. By default `_sgp_sub_` rules only apply to the response with a "textual" [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types), which could be any one of the following: "text/\*", "application/json", "application/xml", "application/atom+xml", "application/x-sh".
- `_sgp_forcesub` : (Value ignored) Force apply `_sgp_sub_` rules to the response of any MIME type.
- `_sgp_cookie=<value>` : Set request cookie. Equivalent to `_sgp_header_cookie=<value>`.
- `_sgp_type=<value>` : Set the request content type. Equivalent to `_sgp_header_Content-Type=<value>`. If `_sgp_method` is set to `POST` and `_sgp_body` is also set, the `_sgp_type` will have a default value `application/x-www-form-urlencoded`.
- `_sgp_restype=<value>` : Set the response content type. Equivalent to `_sgp_resheader_Content-Type=<value>`. Additionally, `_sgp_type` and `_sgp_restype` support file extension values like `txt` or `.txt` (with or without leading dot), in which case it will use the MIME type associated with the file extension ext.
- `_sgp_body=<value>` : Set the request body (String only. Binary data is not supported).
- `_sgp_fdheaders=<header1>,<header2>,...` : Comma-separated forward headers list. For every header in the list, if the http request to the "entrypoint url" itself contains that header, Simplegoproxy will set the request header to the same value when making http request to the "target url". E.g.: `_sgp_fdheaders=Referer,Origin`. A special `*` value can be used to forward ALL request headers. The following headers will ALWAYS be forwarded, even if not specified, unless the same `_sgp_header_*` parameter is set: `Range`, `If-*`; A special "\n" (`%0A`) value supresses this behavior and makes sure no headers would be forwarded.
- `_sgp_user=username:password` : Set the authentication username & password for request. It can also be directly set in target url via "https://user:password@example.com" syntax.
- `_sgp_impersonate=<value>` : Impersonate itself as Browser when sending http request. See below "Impersonate the Browser" section.
- `_sgp_sign=<value>` : The sign of request canonical url. See below "Request signing" section.
- `_sgp_keytype` : The sign key type. See below "Signing key type" section.
- `_sgp_scope=<value>` : The scope of sign. Can be used multiple times. See below "Scope signing" section.
- `_sgp_referer=<value>` : Set the allowed referer of request to the entrypoint url. Can be used multiple times. See below "Referer restrictions" section.
- `_sgp_origin=<value>` : Set the allowed origin of request to the entrypoint url. Can be used multiple times. See below "Origin restrictions" section.
- `_sgp_validbefore=<value>`, `_sgp_validafter=<value>` : If set, the entrypoint url can only be used before or after this time accordingly. Value can be any of below time formats: `2006-01-02`, `2006-01-02T15:04:05` `2006-01-02T15:04:05-07:00`, `2006-01-02T15:04:05Z`. All but the last format are parsed in local timezone. The last one are parsed as UTC time. Note to enforce these restrictions, "Request signing" must be enabled.

Modification paramaters are set in Query Variables. All `_sgp_*` parameters are stripped from the target url when Simplegoproxy fetch it. E.g.: the `http://localhost:3000/https://ipcfg.co/json?abc=1&_sgp_cors` entry will actually fetch the `https://ipcfg.co/json?abc=1` target url.

All "escapable" characters in paramater name & value should be escaped in '%XX' format. (In general, the "escapable" means JavaScript's `encodeURIComponent` function return a escaped string for the char)

## Other features

### Modification parameters fronting

Instead of using Query Variables to set modification parameters, You can also put them in the "path", after the root path but before the target url. E.g.:

```
http://localhost:3000/_sgp_cors/https://ipcfg.co/json
```

### Impersonate the Browser

Simplegoproxy can impersonate itself as Browser when sending http request to target url. It's similar to what [curl-impersonate](https://github.com/lwthiker/curl-impersonate) does. To enable this, set the `_sgp_impersonate` modification parameter to target browser name. E.g.:

```
http://localhost:3000/_sgp_impersonate=chrome120/https://ipcfg.co/json
```

Simplegoproxy will print the list of supported targets when starting. Currently supported impersonates:

- `chrome120` : Chrome 120 on Windows 11 x64 en-US
- `firefox121` : Firefox 121 on Windows 11 x64 en-US

### Admin UI

Simplegoproxy provides a http admin UI at `/admin/` path, e.g. `http://localhost:3000/admin/` . The admin UI allow users to generate entrypoint url for a target url and view history records of generated entrypoint urls. All data are stored in the browser local storage.

### "data:" urls

Simplegoproxy supports `data:` urls ([Data URLs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URLs)), which will use the provided contents directly as the response body.

E.g.

```
http://localhost:3000/data:,Hello%2C%20World%21

http://localhost:3000/data:text/html;base64,SGVsbG8sIFdvcmxkIQ==
```

Both of above entrypoint urls will output "Hello, World!". The later one will also set the `Content-Type: text/html` response header.

### `unix://`, `file://`, `rclone://`, `curl+*//`, `exec://` urls

If `-enable-unix`, `-enable-file`, `-enable-rclone` or `-enable-exec` flag is set, Simplegoproxy will support some additional schemes of urls respectively. If `-enable-all` flag is set, all these schemes will be enabled.

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

For `rclone://`, `curl+*//`, `exec://` urls, if `_sgp_debug` modification parameter is set, it will output the combined stdout and stderr of spawned child process, instead of stdout only.

Note some `_sgp_*` modification parameters don't work with most of above schemes urls, obviously the ones that modify http request.

## Security tips

### Set the rootpath

If your Simplegoproxy instance will be publicly accessible, you can set the "rootpath" flag to a "confidential" value other than the default "/". It acts like a password.

E.g.: If rootpath is set to "/abc/", then the entrypoint url should be like `http://localhost:3000/abc/https://ipcfg.co/json`.

### Request signing

Additional, if "key" flag is set, all requests to Simplegoproxy (except requests of `data:` urls) must be signed via HMAC-SHA256 using the key. The message being signed is the "canonical url" of the request. The result MAC (message authentication code) should be provided in `_sgp_sign` parameter of the request.

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
http://localhost:3000/https://ipinfo.io/ip?_sgp_cors&_sgp_sign=e9ccc14d94cd952d08bef094d9037c26b624a8bf18e6dc6c223d76224d4196ef

# or
http://localhost:3000/_sgp_cors&_sgp_sign=e9ccc14d94cd952d08bef094d9037c26b624a8bf18e6dc6c223d76224d4196ef/https://ipinfo.io/ip

# or
http://localhost:3000/_sgp_sign=e9ccc14d94cd952d08bef094d9037c26b624a8bf18e6dc6c223d76224d4196ef/https://ipinfo.io/ip?_sgp_cors
```

If you pass a `-publicurl http://localhost:3000` flag when invoking the above command, it outputs the final entry url diretly:

```
simplegoproxy -sign -key abc -publicurl "http://localhost:3000" "https://ipinfo.io/ip?_sgp_cors"
https://ipinfo.io/ip?_sgp_cors=  http://localhost:3000/_sgp_sign=e9ccc14d94cd952d08bef094d9037c26b624a8bf18e6dc6c223d76224d4196ef/https://ipinfo.io/ip?_sgp_cors=
```

Note the `data:` urls does not need signing, as they do not actually send any network request or have any side effect.

### Admin UI Authorization

If request signing is enabled, the admin UI will require http basic authorization:

- Username: Default is `root`. Can be changed by `-user string` flag.
- Password: Default use "key" flag as password. Use `-pass string` flag to set standalone password.

### Secret substitutions

If request signing is enabled, all `__SECRET_**__` style substrings in modification parameter value or normal query variable will be replaced with the value of the corresponding `SECRET_**` environment variable, if it exists, when sending request to the target url.

The substitutions occur after the request signing verification.

Note `data:` urls does NOT support secret substitutions.

### Signing key type

It's possible to provide a optional "key type" value whening signing a url. The "key type" value will be appended to the "key" to derive the effective actual HMAC key.

To sign a url, set a `-keytype string` flag:

```
simplegoproxy -key abc -keytype one -sign -publicurl http://localhost:3000 ipinfo.io
```

Output:

```
https://ipinfo.io/  http://localhost:3000/_sgp_keytype=one&_sgp_sign=94bb9904ac8975e1dc3617ca49a9ed4481d7db6626859978dddcd29c3999d3f0/https://ipinfo.io/
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
localhost:3000/_sgp_scope=https%3A%2F%2F%2A%2F%2A/ipinfo.io/ip
```

Here, the `_sgp_scope` is `https://*/*` , which matches all https URLs. The payload ("canonical target url") of scope signing is a `?` character plus all `_sgp_` parameters sorted by key. To calculate it:

```
simplegoproxy -sign -key abc "?_sgp_scope=https://*/\_"
edb3aaafe81cc42ea94a862bb5b77b4876d39ab3748410716bc9d7041e64c715 ?_sgp_scope=https%3A%2F%2F%2A%2F%2A
```

Then use the following entrypoint url:

```
curl -i "localhost:3000/_sgp_sign=edb3aaafe81cc42ea94a862bb5b77b4876d39ab3748410716bc9d7041e64c715&_sgp_scope=https%3A%2F%2F%2A%2F%2A/ipinfo.io/ip"
```

Notes:

- The `_sgp_scope` parameter can be set multiple times. The sign can be used to access any target URL which matches with at least one provided scope.
- A `*` scheme in scope parameter means "http" or "https". E.g. the `*://*/*` scope matches with all "http://" or "https://" urls. If you want to target other schemes like "file" ("file://" url) as well, you must put it in explicitly.

### Referer restrictions

If any `_sgp_referer` parameter is provided. Simplegoproxy will validate the `Referer` header of the request to the entrypoint url and only allow theses requests which referer match with at lease one provided `_sgp_referer` value.

The format of `_sgp_referer` should be a Chrome extension style match pattern (same as `_sgp_scope`). Additionaly, an empty value matches with the "Direct" request, in which case no `Referer` header is present.

Referer restrictions works even if request signing is not enabled.

### Origin restrictions

It works in the same way as the above "Referer restrictions" feature except that the parameter name is `_sgp_origin` and is verified against the `Origin` request header.
