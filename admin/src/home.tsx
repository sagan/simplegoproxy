import React, { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { useSearchParams } from "react-router-dom";
import { useLocalStorage } from "@rehooks/local-storage";
import { Generate, GenerateRequest, fetchParse, fetchGenerate } from "./api.js";
import { generatePassword } from "./funcs.js";

interface InputForm {
  url: string;
  eid: string;
  epath: boolean;
  keytype: string;
  body: string;
  resbody: string;
  cors: boolean;
  nocsp: boolean;
  fdua: boolean;
  fdauth: boolean;
  fdmethod: boolean;
  fdbody: boolean;
  fdtype: boolean;
  debug: boolean;
  addon: string;
  method: string;
  user: string;
  auth: string;
  respass: string;
  type: string;
  restype: string;
  impersonate: string;
  status: number;
  encmode: number;
  authmode: number;
  tplmode: number;
  timeout: number;
  validtime: number;
}

const URL_LENGTH_LIMIT = 2048;
const PASS_LEN = 32;

export default function Home({}) {
  const {
    register,
    reset,
    handleSubmit,
    setValue,
    getValues,
    formState: { errors },
  } = useForm<InputForm>();
  const [urls, setUrls, clearUrls] = useLocalStorage<Generate[]>(
    window.__ROOTPATH__ + "|urls",
    []
  );
  let [searchParams, setSearchParams] = useSearchParams();
  const [copiedIndex, setCopiedIndex] = useState(-1);
  const [filter, setFilter] = useState("");

  const activeReq =
    !!searchParams.get("method") ||
    !!searchParams.get("type") ||
    !!searchParams.get("fdmethod") ||
    !!searchParams.get("fdtype") ||
    !!searchParams.get("user") ||
    !!searchParams.get("fdbody") ||
    !!searchParams.get("impersonate") ||
    !!searchParams.get("body");
  const activeRes =
    !!searchParams.get("status") ||
    !!searchParams.get("auth") ||
    !!searchParams.get("respass") ||
    !!searchParams.get("tplmode") ||
    !!searchParams.get("encmode") ||
    !!searchParams.get("authmode") ||
    !!searchParams.get("resbody") ||
    !!searchParams.get("restype");
  const [showreq, setShowreq] = useState(activeReq);
  const [showres, setShowres] = useState(activeRes);
  const filter_lowercase = filter.toLowerCase();
  let encrypt = !!searchParams.get("encrypt");
  return (
    <>
      <form
        onSubmit={handleSubmit(async (data: InputForm) => {
          setSearchParams(serializeInputForm(data, encrypt));
          if (data.url == "") {
            return;
          }
          try {
            let publicurl = window.__ROOTURL__;
            let url = makeUrl(data, window.__PREFIX__);
            let req: GenerateRequest = { publicurl, url, eid: data.eid.trim() };
            // setValue("url", "");
            let res = await fetchGenerate(req);
            setUrls([res, ...urls]);
          } catch (e) {
            alert(e);
          }
        })}
      >
        <p className="flex flex-wrap">
          <span>
            <a
              title={"Simplegoproxy " + window.__VERSION__}
              href={window.__ADMINPATH__}
              onClick={(e) => {
                e.preventDefault();
                resetParams();
              }}
            >
              SGP
            </a>
            <a title="Github" href="https://github.com/sagan/simplegoproxy">
              ℹ️
            </a>
          </span>
          <input
            type="search"
            className="flex-1"
            placeholder="url"
            autoFocus
            accessKey="f"
            title="[alt+shift+f]"
            {...register("url")}
          />
          <label title="Generated url valid time">
            <select
              defaultValue={parseInt(searchParams.get("validtime")) || 0}
              {...register("validtime", { valueAsNumber: true })}
            >
              <option value="0">(No expire)</option>
              <option value="300">5m valid</option>
              <option value="3600">1h valid</option>
              <option value="86400">1d valid</option>
              <option value="259200">3d valid</option>
              <option value="604800">1w valid</option>
              <option value="2592000">1M valid</option>
              <option value="7776000">3M valid</option>
              <option value="15552000">6M valid</option>
              <option value="31622400">1y valid</option>
              <option value="34300800">13M valid</option>
            </select>
          </label>
          <label
            title={`Encryption url id${errors.eid ? ": invalid input" : ""}`}
          >
            <span>Eid:&nbsp;</span>
            <input
              className={`${errors.eid ? "error" : ""} w-16`}
              defaultValue=""
              type="search"
              {...register("eid", { pattern: /^[_a-zA-Z0-9]*$/ })}
            />
          </label>
          <label title="Encrypt generated entrypoint url">
            <input
              checked={encrypt}
              type="checkbox"
              onChange={(e) => {
                setSearchParams(
                  serializeInputForm(getValues(), e.target.checked)
                );
              }}
            />
            <span>🔒&nbsp;Encrypt</span>
          </label>
          <label title="Allow encrypted url to have plaintext children path and query variables">
            <input
              defaultChecked={!!searchParams.get("epath")}
              type="checkbox"
              {...register("epath")}
            />
            &nbsp;Epath
          </label>
          <button type="submit">Generate</button>
          <button
            type="button"
            onClick={() => {
              let values = getValues();
              reset();
              // react-hook-form problem workaround: in the same callback, reset and setValue can not both take effect
              setTimeout(() => {
                setValue("url", values.url);
              }, 0);
            }}
          >
            Reset
          </button>
          <button
            type="button"
            title="Import a url"
            onClick={async () => {
              let publicurl = window.__ROOTURL__;
              let url = prompt("Input the url:", "");
              if (!url) {
                return;
              }
              try {
                let res = await fetchParse({ url, publicurl });
                setUrls([
                  {
                    url: res.url,
                    encrypted_entryurl: res.encrypted_entryurl,
                    entryurl: res.entryurl,
                    sign: "",
                  },
                  ...urls,
                ]);
              } catch (e) {
                alert(`failed to decrypt: ${e}`);
              }
            }}
          >
            Import
          </button>
        </p>
        <p className="flex flex-wrap">
          <label title="Add the CORS-allow-all headers to original response">
            <input
              defaultChecked={!!searchParams.get("cors")}
              type="checkbox"
              {...register("cors")}
            />
            &nbsp;Cors
          </label>
          <label title="Remove the Content Security Policy (CSP) headers from original response">
            <input
              defaultChecked={!!searchParams.get("nocsp")}
              type="checkbox"
              {...register("nocsp")}
            />
            &nbsp;No csp
          </label>
          <label title="Forward 'User-Agent' request header">
            <input
              defaultChecked={!!searchParams.get("fdua")}
              type="checkbox"
              {...register("fdua")}
            />
            &nbsp;Fd UA
          </label>
          <label title="Forward 'Authorization' request header">
            <input
              defaultChecked={!!searchParams.get("fdauth")}
              type="checkbox"
              {...register("fdauth")}
            />
            &nbsp;Fd Auth
          </label>
          <label title="Debug mode">
            <input
              defaultChecked={!!searchParams.get("debug")}
              type="checkbox"
              {...register("debug")}
            />
            &nbsp;Debug
          </label>
          <label>
            Timeout:&nbsp;
            <input
              type="number"
              className="w-12"
              defaultValue={parseInt(searchParams.get("timeout")) || 0}
              {...register("timeout", { valueAsNumber: true })}
            />
          </label>
          <label>
            Keytype:&nbsp;
            <input
              className="w-16"
              defaultValue={searchParams.get("keytype") || ""}
              {...register("keytype")}
            />
          </label>
          <label title="Set request" className={activeReq ? "active" : ""}>
            <input
              checked={showreq}
              type="checkbox"
              onChange={() => setShowreq(!showreq)}
            />
            &nbsp;Req
          </label>
          <label title="Set response" className={activeRes ? "active" : ""}>
            <input
              checked={showres}
              type="checkbox"
              onChange={() => setShowres(!showres)}
            />
            &nbsp;Res
          </label>
          <label title="Add a parameter to addon">
            Add Parameter&nbsp;
            <select
              defaultValue=""
              onChange={(e) => {
                let value = e.target.value;
                if (value == "") {
                  return;
                }
                value = window.__PREFIX__ + value;
                if (value.indexOf("=") == -1 && !value.endsWith("_")) {
                  value += "=";
                }
                let addon = getValues().addon;
                if (addon != "" && !addon.endsWith("&")) {
                  addon += "&";
                }
                addon += value;
                setValue("addon", addon);
                e.target.value = "";
              }}
            >
              <option value="">(Add)</option>
              <option title="header_Header=value" value="header_">
                header_
              </option>
              <option title="res_header_Header=value" value="resheader_">
                resheader_
              </option>
              <option title="sub_Search=Replacement" value="sub_">
                sub_
              </option>
              <option title="subr_Regexp=Replacement" value="subr_">
                subr_
              </option>
              <option title="subb_HexString=Replacement" value="subb_">
                subb_
              </option>
              <option
                value="subpath"
                title="Do response body substitutions if the url path ends with this value (suffix), e.g. '.txt'"
              >
                subpath
              </option>
              <option
                value="subtype"
                title="Do response body substitutions if the response has this content type, e.g. 'txt' or 'text/plain'"
              >
                subtype
              </option>
              <option title="fdheaders=Header1,Header2" value="fdheaders">
                fdheaders
              </option>
              <option title="referer=http://*.example.com/*" value="referer">
                referer
              </option>
              <option title="origin=http://*.example.com/*" value="origin">
                origin
              </option>
              <option
                title="validbefore=2006-01-02T15:04:05Z"
                value="validbefore"
              >
                validbefore
              </option>
              <option
                title="validafter=2006-01-02T15:04:05Z"
                value="validafter"
              >
                validafter
              </option>
              <option
                title="Use a index file for directory, e.g. 'index.html'"
                value="indexfile"
              >
                indexfile
              </option>
              <option
                value="tplpath"
                title="Do response template if the url path ends with this value (suffix), e.g. '.txt'"
              >
                tplpath
              </option>
              <option
                value="tpltype"
                title="Do response templalte if the response has this content type, e.g. 'txt' or 'text/plain'"
              >
                tpltype
              </option>
              <option
                value="mutetype"
                title="Mute target url original response if it has this content-type, '*' means all but html & txt"
              >
                mutetype
              </option>
              <option
                value="mutepath"
                title="Do not fetch target url if it's path ends with this suffix"
              >
                mutepath
              </option>
              <option
                value="mutestatus"
                title="Mute target url original response if it has this status code, '*' means all but 200 & 206"
              >
                mutestatus
              </option>
              <option title="proxy=socks5://1.2.3.4:1080" value="proxy">
                proxy
              </option>
              <option value="scope=">scope</option>
              <option value="scope=*://*/*">scope=*</option>
              <option title="Render markdown to html" value="md2html=1">
                md2html=1
              </option>
              <option title="Set no-cache header on response" value="nocache=1">
                nocache=1
              </option>
              <option
                title="Trim most response headers except Content-Type/Length/Encoding/Range"
                value="trimresheader=1"
              >
                trimresheader=1
              </option>
              <option
                title="Force do string substitions on any type response"
                value="forcesub=1"
              >
                forcesub=1
              </option>
              <option title="No redirect following" value="norf=1">
                norf=1
              </option>
              <option
                title="Disable TLS/SSL cert verifications"
                value="insecure=1"
              >
                insecure=1
              </option>
            </select>
            &nbsp;=&nbsp;
            <span>
              <button
                title="Add parameter value"
                type="button"
                onClick={() => {
                  let value = (prompt("Input a value to encode") || "").trim();
                  if (!value) {
                    return;
                  }
                  let addon = getValues().addon;
                  if (
                    addon.length > 0 &&
                    !addon.endsWith("=") &&
                    !addon.endsWith("_")
                  ) {
                    addon += "=";
                  }
                  addon += encodeURIComponent(value);
                  setValue("addon", addon);
                }}
              >
                SetValue
              </button>
              <button
                title="Add env value"
                type="button"
                onClick={() => {
                  let value = (prompt("Input env variable name") || "").trim();
                  if (!value) {
                    return;
                  }
                  let addon = getValues().addon;
                  addon += "__SGPENV_" + value + "__";
                  setValue("addon", addon);
                }}
              >
                SetEnv
              </button>
              <button
                title="Delete last parameter name or value"
                type="button"
                onClick={() => {
                  let addon = getValues().addon;
                  let i = -1;
                  if (addon.endsWith("=")) {
                    i = addon.lastIndexOf("&");
                  } else {
                    i = addon.lastIndexOf("=");
                    if (i != -1) {
                      i++;
                    }
                  }
                  if (i != -1) {
                    addon = addon.substring(0, i);
                  } else {
                    addon = "";
                  }
                  setValue("addon", addon);
                }}
              >
                Delete
              </button>
            </span>
          </label>
        </p>
        <p className="flex">
          <textarea
            placeholder="addon"
            defaultValue={searchParams.get("addon") || ""}
            className="flex-1"
            {...register("addon")}
          />
        </p>
        {showreq && (
          <>
            <p className="flex flex-wrap">
              <label title="Http request method">
                Method&nbsp;
                <select
                  defaultValue={searchParams.get("method")}
                  {...register("method")}
                >
                  <option value="">(Default)</option>
                  <option value="GET">GET</option>
                  <option value="PUT">PUT</option>
                  <option value="POST">POST</option>
                  <option value="DELETE">DELETE</option>
                </select>
              </label>
              <label title="Http request content type">
                Type&nbsp;
                <select
                  defaultValue={searchParams.get("type")}
                  {...register("type")}
                >
                  <option value="">(Default)</option>
                  <option value="application/x-www-form-urlencoded">
                    application/x-www-form-urlencoded
                  </option>
                  <option value="multipart/form-data">
                    multipart/form-data
                  </option>
                  <option value="txt">txt</option>
                  <option value="json">json</option>
                  <option value="xml">xml</option>
                </select>
              </label>
              <label title="Forward http request method">
                <input
                  defaultChecked={!!searchParams.get("fdmethod")}
                  type="checkbox"
                  {...register("fdmethod")}
                />
                &nbsp;Fd Method
              </label>
              <label title="Forward http request Content-Type">
                <input
                  defaultChecked={!!searchParams.get("fdtype")}
                  type="checkbox"
                  {...register("fdtype")}
                />
                &nbsp;Fd Type
              </label>
              <label title="Forward http request body">
                <input
                  defaultChecked={!!searchParams.get("fdbody")}
                  type="checkbox"
                  {...register("fdbody")}
                />
                &nbsp;Fd Body
              </label>
              <label title="Target url http request basic auth user">
                <span>User:&nbsp;</span>
                <input
                  className="w-16"
                  placeholder="user:pass"
                  defaultValue={searchParams.get("user") || ""}
                  {...register("user")}
                />
              </label>
              <label title="Http request impersonate browser">
                Impersonate:&nbsp;
                <select
                  defaultValue={searchParams.get("impersonate")}
                  {...register("impersonate")}
                >
                  <option value="">(default)</option>
                  <option value="chrome120">chrome120</option>
                  <option value="firefox121">firefox121</option>
                </select>
              </label>
            </p>
            <p className="flex">
              <textarea
                className="flex-1"
                placeholder="body"
                defaultValue={searchParams.get("body") || ""}
                {...register("body")}
              />
            </p>
          </>
        )}
        {showres && (
          <>
            <p className="flex flex-wrap">
              <label title="Http response status">
                Status&nbsp;
                <select
                  defaultValue={parseInt(searchParams.get("status")) || 0}
                  {...register("status", { valueAsNumber: true })}
                >
                  <option value="0">(Default)</option>
                  <option
                    value="-1"
                    title="Always use original target url http response status"
                  >
                    Original
                  </option>
                  <option value="200">200</option>
                  <option value="401">401</option>
                  <option value="403">403</option>
                  <option value="404">404</option>
                  <option value="500">500</option>
                  <option value="503">503</option>
                </select>
              </label>
              <label title="Http response content type">
                Restype&nbsp;
                <select
                  defaultValue={searchParams.get("restype")}
                  {...register("restype")}
                >
                  <option value="">(Default)</option>
                  <option
                    value="*"
                    title="Automatically guess response content-type from current url path suffix"
                  >
                    * (auto)
                  </option>
                  <option value="txt">txt</option>
                  <option value="html">html</option>
                  <option value="xml">xml</option>
                  <option value="json">json</option>
                  <option value="yaml">yaml</option>
                  <option value="js">js</option>
                  <option value="css">css</option>
                </select>
              </label>
              <label title="Http authentication to the entrypoint url">
                <span>Auth:&nbsp;🪪</span>
                <input
                  placeholder="user:pass"
                  className="w-16"
                  defaultValue={searchParams.get("auth") || ""}
                  {...register("auth")}
                />
                <button
                  type="button"
                  title="Generate a random authorization password"
                  onClick={() => {
                    let auth = getValues().auth.trim();
                    let [user] = auth.split(":");
                    auth = (user || "user") + ":" + generatePassword(PASS_LEN);
                    setValue("auth", auth);
                  }}
                >
                  🎲
                </button>
                <select
                  title="Http response authorization mode"
                  defaultValue={parseInt(searchParams.get("authmode")) || 0}
                  {...register("authmode", { valueAsNumber: true })}
                >
                  <option value="0" title="Basic Auth (0)">
                    Basic
                  </option>
                  <option value="1" title="Digest Auth (1)">
                    Digest
                  </option>
                </select>
              </label>
              <label title="Password to encrypt response">
                <span>Respass:&nbsp;🔑</span>
                <input
                  className="w-16"
                  defaultValue={searchParams.get("respass") || ""}
                  {...register("respass")}
                />
                <button
                  type="button"
                  title="Generate a random encryption password"
                  onClick={() => {
                    setValue("respass", generatePassword(PASS_LEN));
                  }}
                >
                  🎲
                </button>
                <select
                  defaultValue={parseInt(searchParams.get("encmode")) || 0}
                  {...register("encmode", { valueAsNumber: true })}
                >
                  <option value="0">(Default encryption mode) (0)</option>
                  <option value="1">binary response (1)</option>
                  <option value="2">body only encryption (2)</option>
                  <option value="3">Binary(1)+BodyOnly(2)</option>
                  <option value="4">full protection (4)</option>
                  <option value="5">Full(4)+Binary(1)</option>
                  <option value="12">Full(4)+TextBody(8)</option>
                  <option value="20">Full(4)+BinBody(16)</option>
                  <option value="13">Full(4)+TextBody(8)+Binary(1)</option>
                  <option value="21">Full(4)+BinBody(16)+Binary(1)</option>
                </select>
              </label>
              <label title="Response template mode">
                Tplmode&nbsp;
                <select
                  defaultValue={parseInt(searchParams.get("tplmode")) || 0}
                  {...register("tplmode", { valueAsNumber: true })}
                >
                  <option value="0">(None)</option>
                  <option
                    value="1"
                    title="Always use text template (never use html template)"
                  >
                    Text template (1)
                  </option>
                  <option
                    value="2"
                    title="Use original response body as template"
                  >
                    BodyTpl (2)
                  </option>
                  <option
                    value="4"
                    title="Do not read original response body prior renderring template"
                  >
                    NoOriginalBody (4)
                  </option>
                  <option value="8" title="Always do response template">
                    AlwaysDo (8)
                  </option>
                  <option
                    value="16"
                    title="Keep the content-type of original response unchanged"
                  >
                    KeepType (16)
                  </option>
                  <option value="3">Text(1)+BodyType(2)</option>
                  <option value="5">Text(1)+NoOriginalBody(4)</option>
                  <option value="11">Text(1)+BT(2)+A(8)</option>
                  <option value="13">Text(1)+NOB(4)+A(8)</option>
                  <option value="19">Text(1)+BT(2)+KT(16)</option>
                  <option value="21">Text(1)+NOB(4)+KT(16)</option>
                  <option value="27">Text(1)+BT(2)+A(8)+KT(16)</option>
                  <option value="29">Text(1)+NOB(4)+A(8)+KT(16)</option>
                </select>
              </label>
            </p>
            <p className="flex">
              <textarea
                className="flex-1"
                placeholder="resbody"
                defaultValue={searchParams.get("resbody") || ""}
                {...register("resbody")}
              />
            </p>
          </>
        )}
      </form>
      <div className="flex-1 overflow-auto">
        <h2 className="flex">
          <span className="flex-1">
            <span>Generated Urls (Stored locally)</span>
            <input
              type="search"
              placeholder="filter"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </span>
          <span>
            <button
              type="button"
              title="Delete all records"
              onClick={() => {
                if (!confirm("Clear history?")) {
                  return;
                }
                setUrls([]);
                setCopiedIndex(-1);
              }}
            >
              XX
            </button>
          </span>
        </h2>
        <table className="mt-1 urls">
          <thead>
            <tr>
              <td className="w-1/12">#</td>
              <td className="w-4/12">Target</td>
              <td className="w-5/12">Url</td>
              <td className="w-2/12">@</td>
            </tr>
          </thead>
          <tbody>
            {urls.map((url, i) => {
              let index = urls.length - i;
              let needauth = false;
              let res_encrypted = false;
              let validbefore = "";
              try {
                let urlObj = new URL(url.url);
                // URL.prototype.get return null for non-exists value !
                res_encrypted = !!urlObj.searchParams.get(
                  window.__PREFIX__ + "respass"
                );
                needauth = !!urlObj.searchParams.get(
                  window.__PREFIX__ + "auth"
                );
                validbefore =
                  urlObj.searchParams.get(window.__PREFIX__ + "validbefore") ||
                  "";
              } catch (e) {}
              let accessurl = url.entryurl;
              let encryptedUrl = false;
              if (
                (url.encrypted_entryurl != "" &&
                  (encrypt || needauth || res_encrypted)) ||
                (accessurl == "" && url.encrypted_entryurl != "")
              ) {
                accessurl = url.encrypted_entryurl;
                encryptedUrl = true;
              }
              let display =
                index == urls.length ||
                url.url.toLowerCase().indexOf(filter_lowercase) != -1;
              if (!display) {
                return null;
              }
              return (
                <tr key={i} className="url">
                  <td>{index}</td>
                  <td className="targeturl">
                    <a href={url.url}>
                      {url.url.length > URL_LENGTH_LIMIT
                        ? url.url.substring(0, URL_LENGTH_LIMIT) + "..."
                        : url.url}
                    </a>
                  </td>
                  <td className="accessurl">
                    <a href={accessurl}>
                      {accessurl.length > URL_LENGTH_LIMIT
                        ? accessurl.substring(0, URL_LENGTH_LIMIT) + "..."
                        : accessurl}
                    </a>
                    {encryptedUrl && (
                      <span className="icon" title="URL is encrypted">
                        🔒
                      </span>
                    )}
                    {needauth && (
                      <span
                        className="icon"
                        title="Request to the entrypoint url needs authentication"
                      >
                        🪪
                      </span>
                    )}
                    {res_encrypted && (
                      <span className="icon" title="Http response is encrypted">
                        🔑
                      </span>
                    )}
                    {validbefore != "" && (
                      <span
                        className="icon"
                        title={`Valid before ${validbefore}`}
                      >
                        ⏰
                      </span>
                    )}
                  </td>
                  <td>
                    <button
                      onClick={async () => {
                        try {
                          navigator.clipboard.writeText(accessurl);
                          setCopiedIndex(index);
                        } catch (e) {
                          alert(`fail to copy: ${e}`);
                        }
                      }}
                    >
                      {copiedIndex == index ? "✓Copied" : "Copy"}
                    </button>
                    <button
                      title="Delete"
                      onClick={async () => {
                        if (!confirm(`Delete ${url.entryurl}`)) {
                          return;
                        }
                        let newUrls = urls.slice();
                        newUrls.splice(i, 1);
                        if (copiedIndex == index) {
                          setCopiedIndex(-1);
                        } else if (copiedIndex > index) {
                          setCopiedIndex(copiedIndex - 1);
                        }
                        setUrls(newUrls);
                      }}
                    >
                      X
                    </button>
                    <button
                      title="Use this url again"
                      onClick={() => {
                        let urlObj = new URL(url.url);
                        let params: string[][] = [];
                        for (const [key, value] of urlObj.searchParams) {
                          params.push([key, value]);
                        }
                        let searchParams = new URLSearchParams();
                        for (let [key, value] of params) {
                          if (
                            key.startsWith(window.__PREFIX__) &&
                            key.length > window.__PREFIX__.length
                          ) {
                            searchParams.append(key, value);
                            urlObj.searchParams.delete(key, value);
                            continue;
                          }
                        }
                        setValue("url", urlObj.href);
                        resetParams(searchParams);
                      }}
                    >
                      Use
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );

  function resetParams(searchParams: URLSearchParams = new URLSearchParams()) {
    let values = NewInputForm();
    values.addon = searchParams.get("addon") || "";
    searchParams.delete("addon");
    for (let [key, value] of searchParams) {
      if (
        !key.startsWith(window.__PREFIX__) ||
        key.length == window.__PREFIX__.length
      ) {
        continue;
      }
      key = key.substring(window.__PREFIX__.length);
      if (values[key] !== undefined) {
        switch (typeof values[key]) {
          case "boolean":
            if (value) {
              values[key] = true;
            }
            break;
          case "number":
            if (value) {
              values[key] = parseInt(value) || 0;
            }
            break;
          case "string":
            if (value) {
              values[key] = value;
            }
        }
      } else if (key != "sign") {
        if (values.addon != "") {
          values.addon += "&";
        }
        if (key == "fdheaders") {
          let fdheaders = value.split(/\s*,\s*/);
          let i = -1;
          i = fdheaders.indexOf("Authorization");
          if (i != -1) {
            values.fdauth = true;
            fdheaders.splice(i, 1);
          }
          i = fdheaders.indexOf("Content-Type");
          if (i != -1) {
            values.fdtype = true;
            fdheaders.splice(i, 1);
          }
          i = fdheaders.indexOf("User-Agent");
          if (i != -1) {
            values.fdua = true;
            fdheaders.splice(i, 1);
          }
          i = fdheaders.indexOf(":method");
          if (i != -1) {
            values.fdmethod = true;
            fdheaders.splice(i, 1);
          }
          i = fdheaders.indexOf(":body");
          if (i != -1) {
            values.fdbody = true;
            fdheaders.splice(i, 1);
          }
          value = fdheaders.join(",");
          if (value == "") {
            continue;
          }
        }
        values.addon +=
          window.__PREFIX__ + key + "=" + encodeURIComponent(value);
      }
    }
    let option = {
      shouldDirty: true,
      shouldTouch: true,
    };
    setValue("fdua", values.fdua, option);
    setValue("fdauth", values.fdauth, option);
    setValue("fdmethod", values.fdmethod, option);
    setValue("fdbody", values.fdbody, option);
    setValue("fdtype", values.fdtype, option);
    setValue("method", values.method, option);
    setValue("user", values.user, option);
    setValue("auth", values.auth, option);
    setValue("respass", values.respass, option);
    setValue("cors", values.cors, option);
    setValue("nocsp", values.nocsp, option);
    setValue("debug", values.debug, option);
    setValue("keytype", values.keytype, option);
    setValue("addon", values.addon, option);
    setValue("timeout", values.timeout, option);
    setValue("validtime", values.validtime, option);
    setValue("tplmode", values.tplmode, option);
    setValue("encmode", values.encmode, option);
    setValue("authmode", values.authmode, option);
    setValue("body", values.body, option);
    setValue("type", values.type, option);
    setValue("resbody", values.resbody, option);
    setValue("restype", values.restype, option);
    setValue("status", values.status, option);
    setValue("eid", values.eid, option);
    setValue("epath", values.epath, option);
    setValue("impersonate", values.impersonate, option);
    setSearchParams(serializeInputForm(getValues(), encrypt));
  }
}

function makeUrl(data: InputForm, prefix: string): string {
  let {
    url,
    validtime,
    fdua,
    fdauth,
    fdmethod,
    fdbody,
    fdtype,
    addon,
    ...others
  } = data;
  // Unlike go's url.Parse, JavaScript's URL refues to handle schemeless url
  url = url.trim();
  if (
    !url.match(
      /^((https?|unix|file|rclone|exec|curl\+[a-z][a-z0-9]*):\/\/|data:)/i
    )
  ) {
    url = "https://" + url;
  }
  let urlObj = new URL(url);
  for (let key in others) {
    let value = "";
    if (typeof others[key] == "boolean") {
      if (!others[key]) {
        continue;
      }
      value = "1";
    } else if (typeof others[key] == "number") {
      if (!others[key]) {
        continue;
      }
      value = `${others[key]}`;
    } else {
      value = `${others[key]}`.trim();
      if (value == "") {
        continue;
      }
    }
    urlObj.searchParams.set(prefix + key, value);
  }
  let FDHEADERS = prefix + "fdheaders";
  let fdheadersStr = urlObj.searchParams.get(FDHEADERS) || "";
  let fdheaders = fdheadersStr == "" ? [] : fdheadersStr.split(/,/);
  if (fdua && fdheaders.indexOf("User-Agent") == -1) {
    fdheaders.push("User-Agent");
  }
  if (fdauth && fdheaders.indexOf("Authorization") == -1) {
    fdheaders.push("Authorization");
  }
  if (fdtype && fdheaders.indexOf("Content-Type") == -1) {
    fdheaders.push("Content-Type");
  }
  if (fdmethod && fdheaders.indexOf(":method") == -1) {
    fdheaders.push(":method");
  }
  if (fdbody && fdheaders.indexOf(":body") == -1) {
    fdheaders.push(":body");
  }
  if (fdheaders.length > 0) {
    urlObj.searchParams.set(FDHEADERS, fdheaders.join(","));
  }
  if (validtime > 0) {
    let validbefore = new Date(+new Date() + validtime * 1000).toISOString(); // "2011-10-05T14:48:00.000Z"
    validbefore = validbefore.substring(0, 19) + "Z"; // "2011-10-05T14:48:00Z"
    urlObj.searchParams.set(prefix + "validbefore", validbefore);
  }
  if (addon != "") {
    let params = new URLSearchParams(addon);
    for (const [key, value] of params) {
      urlObj.searchParams.append(key, value);
    }
  }
  return urlObj.href;
}

function serializeInputForm(
  data: InputForm,
  encrypt: boolean
): URLSearchParams {
  let values: {
    [key: string]: any;
  } = {};
  for (let key in data) {
    if (key == "url" || key == "eid") {
      continue;
    }
    if (typeof data[key] == "boolean") {
      if (data[key]) {
        values[key] = "1";
      }
    } else if (data[key]) {
      values[key] = data[key];
    }
  }
  if (encrypt) {
    values["encrypt"] = 1;
  }
  return new URLSearchParams(values);
}

function NewInputForm(): InputForm {
  return {
    url: "",
    keytype: "",
    body: "",
    resbody: "",
    cors: false,
    nocsp: false,
    fdua: false,
    fdauth: false,
    debug: false,
    addon: "",
    timeout: 0,
    status: 0,
    encmode: 0,
    authmode: 0,
    tplmode: 0,
    validtime: 0,
    fdmethod: false,
    fdbody: false,
    fdtype: false,
    epath: false,
    method: "",
    auth: "",
    respass: "",
    eid: "",
    restype: "",
    type: "",
    user: "",
    impersonate: "",
  };
}
