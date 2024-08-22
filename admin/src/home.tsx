import React, { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { useSearchParams } from "react-router-dom";
import { useLocalStorage } from "@rehooks/local-storage";
import {
  Generate,
  GenerateRequest,
  fetchDecrypt,
  fetchGenerate,
} from "./api.js";

interface InputForm {
  url: string;
  eid: string;
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
  scope: string;
  method: string;
  respass: string;
  type: string;
  restype: string;
  timeout: number;
}

const URL_LENGTH_LIMIT = 2048;

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
    !!searchParams.get("fdbody") ||
    !!searchParams.get("body");
  const activeRes =
    !!searchParams.get("resbody") ||
    !!searchParams.get("restype") ||
    !!searchParams.get("respass");
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
          <a
            title={"Simplegoproxy " + window.__VERSION__}
            href="https://github.com/sagan/simplegoproxy"
          >
            SGP
          </a>
          <input
            type="search"
            className="flex-1"
            placeholder="url"
            autoFocus
            {...register("url")}
          />
          <label
            title={`Encryption url id${errors.eid ? ": invalid input" : ""}`}
          >
            <span>Eid:&nbsp;</span>
            <input
              className={errors.eid ? "error" : ""}
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
            title="Decrypt a encrypted url"
            onClick={async () => {
              let publicurl = window.__ROOTURL__;
              let encryptedurl = prompt("Input the encrypted url:", "");
              if (!encryptedurl) {
                return;
              }
              try {
                let res = await fetchDecrypt({ encryptedurl, publicurl });
                setUrls([
                  {
                    url: res.url,
                    encrypted_entryurl: res.encrypted_entryurl,
                    entryurl: "",
                    sign: "",
                  },
                  ...urls,
                ]);
              } catch (e) {
                alert(`failed to decrypt: ${e}`);
              }
            }}
          >
            Decrypt
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
            &nbsp;Forward UA
          </label>
          <label title="Forward 'Authorization' request header">
            <input
              defaultChecked={!!searchParams.get("fdauth")}
              type="checkbox"
              {...register("fdauth")}
            />
            &nbsp;Forward Auth
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
              defaultValue={parseInt(searchParams.get("timeout")) || 0}
              {...register("timeout", { valueAsNumber: true })}
            />
          </label>
          <label>
            Keytype:&nbsp;
            <input
              defaultValue={searchParams.get("keytype") || ""}
              {...register("keytype")}
            />
          </label>
          <label>
            Scope:&nbsp;
            <input
              defaultValue={searchParams.get("scope") || ""}
              {...register("scope")}
            />
          </label>
          <label className="flex flex-1">
            <span>Addon:&nbsp;</span>
            <input
              defaultValue={searchParams.get("addon") || ""}
              className="flex-1"
              {...register("addon")}
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
        </p>
        {showreq && (
          <>
            <p className="flex">
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
                &nbsp;Forward Method
              </label>
              <label title="Forward http request Content-Type">
                <input
                  defaultChecked={!!searchParams.get("fdtype")}
                  type="checkbox"
                  {...register("fdtype")}
                />
                &nbsp;Forward Content-Type
              </label>
              <label title="Forward http request body">
                <input
                  defaultChecked={!!searchParams.get("fdbody")}
                  type="checkbox"
                  {...register("fdbody")}
                />
                &nbsp;Forward Body
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
            <p className="flex">
              <label title="Http response content type">
                Restype&nbsp;
                <select
                  defaultValue={searchParams.get("restype")}
                  {...register("restype")}
                >
                  <option value="">(Default)</option>
                  <option value="txt">txt</option>
                  <option value="html">html</option>
                  <option value="xml">xml</option>
                  <option value="json">json</option>
                  <option value="yaml">yaml</option>
                </select>
              </label>
              <label title="Password to encrypt response body">
                <span>Respass:&nbsp;🔑</span>
                <input
                  defaultValue={searchParams.get("respass") || ""}
                  {...register("respass")}
                />
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
              let res_encrypted = false;
              try {
                let urlObj = new URL(url.url);
                // URL.prototype.get return null for non-exists value !
                res_encrypted = !!urlObj.searchParams.get(
                  window.__PREFIX__ + "respass"
                );
              } catch (e) {}
              let accessurl = url.entryurl;
              let encryptedUrl = false;
              if (
                (url.encrypted_entryurl != "" && (encrypt || res_encrypted)) ||
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
                    {encryptedUrl && <span>🔒</span>}
                    {res_encrypted && <span>🔑</span>}
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
                        try {
                          let urlObj = new URL(url.url);
                          let values: InputForm = {
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
                            scope: "",
                            timeout: 0,
                            fdmethod: false,
                            fdbody: false,
                            fdtype: false,
                            method: "",
                            respass: "",
                            eid: "",
                            restype: "",
                            type: "",
                          };
                          let params: string[][] = [];
                          for (const [key, value] of urlObj.searchParams) {
                            params.push([key, value]);
                          }
                          for (let [key, value] of params) {
                            if (
                              !key.startsWith(window.__PREFIX__) ||
                              key.length == window.__PREFIX__.length
                            ) {
                              continue;
                            }
                            urlObj.searchParams.delete(key, value);
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
                                window.__PREFIX__ +
                                key +
                                "=" +
                                encodeURIComponent(value);
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
                          setValue("respass", values.respass, option);
                          setValue("cors", values.cors, option);
                          setValue("nocsp", values.nocsp, option);
                          setValue("debug", values.debug, option);
                          setValue("keytype", values.keytype, option);
                          setValue("scope", values.scope, option);
                          setValue("addon", values.addon, option);
                          setValue("timeout", values.timeout, option);
                          setValue("body", values.body, option);
                          setValue("type", values.type, option);
                          setValue("resbody", values.resbody, option);
                          setValue("restype", values.restype, option);
                          setValue("url", urlObj.href, option);
                          setValue("eid", values.eid, option);
                        } catch (e) {
                          alert(`${e}`);
                        }
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
}

function makeUrl(data: InputForm, prefix: string): string {
  let { url, fdua, fdauth, fdmethod, fdbody, fdtype, addon, ...others } = data;
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
