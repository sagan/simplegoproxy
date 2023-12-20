# simplegoproxy

Simplegoproxy is a Web / API proxy that can, and is designed and intended to be used to modify the http request headers, response headers and / or response body on the fly, based on custom rules per request, and then return the modified response to the user.

Use cases:

* Remove CORS restrictions.
* Add "Authorization" or other headers to the request.
* Apply string replacements on the response body.

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

Append the target url to the root path to access it from Simplegoproxy. E.g. (Simplegoproxy is started with the default "/' root path):

```
curl -i "localhost:3000/https://ipcfg.co/json"
```

By default it will just fetch the url and return the original response, without any modification. Add specic query parameters to set the modification rules. For example:

```
curl -i "localhost:3000/https://ipcfg.co/json?_sgp_cors"
```

The ```_sgp_cors``` modification query parameter indicates Simplegoproxy to modify the original response headers to set the CORS-allow-all headers:

```
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, OPTIONS
Access-Control-Allow-Origin: *
```

## Modification query parameters

All modification query paramaters has the `_sgp_` prefix by default, which can be changed via ```-prefix``` command-line argument.

Modification query parameter are stripped from the target url when Simplegoproxy fetch it.

* ```_sgp_cors``` : (Value ignored) Add the CORS-allow-all headers to original response.
* ```_sgp_nocsp``` : (Value ignored) Remove the [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) (CSP) headers from original response.
* ```_sgp_insecure``` : (Value ignored) Ignore any TLS cert error in http request.
* ```_sgp_proxy=socks5://1.2.3.4:1080``` : Set the proxy for the http request.
* ```_sgp_timeout=5``` : Set the timeout for the http request (seconds).
* ```_sgp_header_<any>=<value>``` : Set the request header. E.g. `_sgp_header_Authorization=Token%20abcdef` will set the "Authorization: Token abcdef" request header. If value is empty, will remove the target header from request.
* ```_sgp_resheader_<any>=<value>``` : Similar to ```_sgp_header_```, but set or remove the response header.
* ```_sgp_sub_<string>=<replacement>``` : Similar to nginx [http_sub](https://nginx.org/en/docs/http/ngx_http_sub_module.html) module, modifiy the response by replacing one specified string by another. By default ```_sgp_sub_``` rules only apply to the response with any MIME type of the following: "text/html", "application/json", "text/json", "text/plain", "text/csv".
* ```_sgp_forcesub``` : (Value ignored) Force apply ```_sgp_sub_``` rules to the response of any MIME type.

## Security tip

If your Simplegoproxy instance will be publicly accessible, make sure to set the "rootpath" argument to a "confidential" value other than the default "/". It acts like a password.