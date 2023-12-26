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

Command-line arguments:

```
-port int
      Http listening port (default 3000) (can also be set with PORT env)
-prefix string
      Prefix of settings in query parameters (default "_sgp_") (can also be set with PREFIX env)
-rootpath string
      Root path (with leading and trailing slash) (default "/") (can also be set with ROOTPATH env)
```

All arguments are optional, and can also be set by environment variable with the same name in uppercase.

## Usage

Append the target url to the root path to generate the "entrypoint url". E.g. (Assume Simplegoproxy is started with the default "/' root path):

```
curl -i "localhost:3000/https://ipcfg.co/json"
```

The "entrypoint url" accepts GET requests only. By default it will just fetch the "target url" and return the original response, without any modification. Add specic query parameters to set the modification rules. For example:

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
- `_sgp_proxy=socks5://1.2.3.4:1080` : Set the proxy for the http request.
- `_sgp_timeout=5` : Set the timeout for the http request (seconds).
- `_sgp_method=GET` : Set the method for the http request. Default to `GET`.
- `_sgp_header_<any>=<value>` : Set the request header. E.g. `_sgp_header_Authorization=Token%20abcdef` will set the "Authorization: Token abcdef" request header. If value is empty, will remove the target header from request.
- `_sgp_resheader_<any>=<value>` : Similar to `_sgp_header_`, but set or remove the response header.
- `_sgp_sub_<string>=<replacement>` : Similar to nginx [http_sub](https://nginx.org/en/docs/http/ngx_http_sub_module.html) module, modifiy the response by replacing one specified string by another. By default `_sgp_sub_` rules only apply to the response with a "textual" [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types), which could be any one of the following: "text/\*", "application/json", "application/xml", "application/atom+xml", "application/x-sh".
- `_sgp_forcesub` : (Value ignored) Force apply `_sgp_sub_` rules to the response of any MIME type.
- `_sgp_cookie=<value>` : Set request cookie. Equivalent to `_sgp_header_cookie=<value>`.
- `_sgp_type=<value>` : Set the request content type. Equivalent to `_sgp_header_Content-Type=<value>`. If `_sgp_method` is set to `POST` and `_sgp_body` is also set, the `_sgp_type` will have a default value `application/x-www-form-urlencoded`.
- `_sgp_body=<value>` : Set the request body (String only. Binary data is not supported).
- `_sgp_fdheaders=<header1>,<header2>,...` : Comma-separated forward headers list. For every header in the list, if the http request to the "entrypoint url" itself contains that header, Simplegoproxy will set the request header to the same value when making http request to the "target url". E.g.: `_sgp_fdheaders=Referer,Origin`. Note the following headers will ALWAYS be "forwarded", even if not set: "Range", "If-Range".
- `_sgp_basicauth=user:password` : Set the HTTP Basic Authentication for request. It can also be directly set in target url via "https://user:password@example.com" syntax.
- `_sgp_impersonate=<value>` : Impersonate itself as Browser when sending http request. See below.

Modification paramaters are set in Query Variables. All parameters with `_sgp_` prefix are stripped from the target url when Simplegoproxy fetch it. For example the `http://localhost:3000/https://ipcfg.co/json?abc=1&_sgp_cors` entry will actually fetch the `https://ipcfg.co/json?abc=1` target url.

## Other tips

### Modification parameters fronting

Instead of using Query Variables to set modification parameters, You can also put them in the "path", after the root path but before the target url. E.g. :

```
http://localhost:3000/_sgp_cors/https://ipcfg.co/json
```

### Impersonate the Browser

Simplegoproxy can impersonate itself as Browser when sending http request to target url. It's similar to what [curl-impersonate](https://github.com/lwthiker/curl-impersonate) does. To enable this, set the `_sgp_impersonate` modification parameter to target browser name. E.g. :

```
http://localhost:3000/_sgp_impersonate=chrome120/https://ipcfg.co/json
```

Currently, only `chrome120` (Chrome v120 on Windows 11 en-US) target is supported. Simplegoproxy will print the list of supported targets when starting.

### Security tip

If your Simplegoproxy instance will be publicly accessible, make sure to set the "rootpath" argument to a "confidential" value other than the default "/". It acts like a password.

E.g. If rootpath is set to "/abc/", then access the target url via `http://localhost:3000/abc/https://ipcfg.co/json`.
