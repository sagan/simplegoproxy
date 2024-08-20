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
  const [showbody, setShowbody] = useState(!!searchParams.get("body"));
  const [showresbody, setShowresbody] = useState(
    !!searchParams.get("method") ||
      !!searchParams.get("resbody") ||
      !!searchParams.get("fdmethod") ||
      !!searchParams.get("fdbody") ||
      !!searchParams.get("fdtype")
  );
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
            let req: GenerateRequest = { publicurl, url };
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
            &nbsp;Encrypt
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
            &nbsp;cors
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
            timeout:&nbsp;
            <input
              type="number"
              defaultValue={parseInt(searchParams.get("timeout")) || 0}
              {...register("timeout", { valueAsNumber: true })}
            />
          </label>
          <label>
            keytype:&nbsp;
            <input
              defaultValue={searchParams.get("keytype") || ""}
              {...register("keytype")}
            />
          </label>
          <label>
            scope:&nbsp;
            <input
              defaultValue={searchParams.get("scope") || ""}
              {...register("scope")}
            />
          </label>
          <label className="flex flex-1">
            <span>addon:&nbsp;</span>
            <input
              defaultValue={searchParams.get("addon") || ""}
              className="flex-1"
              {...register("addon")}
            />
          </label>
          <label title="Set request body ">
            <input
              checked={showbody}
              type="checkbox"
              onChange={() => setShowbody(!showbody)}
            />
            &nbsp;Body
          </label>
          <label title="Set response body ">
            <input
              checked={showresbody}
              type="checkbox"
              onChange={() => setShowresbody(!showresbody)}
            />
            &nbsp;ResBody
          </label>
        </p>
        {showbody && (
          <p className="flex">
            <textarea
              className="flex-1"
              placeholder="body"
              defaultValue={searchParams.get("body") || ""}
              {...register("body")}
            />
          </p>
        )}
        {showresbody && (
          <>
            <p className="flex">
              <label title="Forward http request method">
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
              <label title="Forward http request method">
                <input
                  defaultChecked={!!searchParams.get("fdmethod")}
                  type="checkbox"
                  {...register("fdmethod")}
                />
                &nbsp;Forward Method
              </label>
              <label title="Forward http request body">
                <input
                  defaultChecked={!!searchParams.get("fdbody")}
                  type="checkbox"
                  {...register("fdbody")}
                />
                &nbsp;Forward Body
              </label>
              <label title="Forward http request Content-Type">
                <input
                  defaultChecked={!!searchParams.get("fdtype")}
                  type="checkbox"
                  {...register("fdtype")}
                />
                &nbsp;Forward Content-Type
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
          <span className="flex-1">Generated Urls (Stored locally)</span>
          <span>
            <input
              type="text"
              placeholder="filter"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <button
              type="button"
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
        <table className="mt-1">
          <thead>
            <tr>
              <td>#</td>
              <td>Target</td>
              <td>Url</td>
              <td>@</td>
            </tr>
          </thead>
          <tbody>
            {urls.map((url, i) => {
              let index = urls.length - i;
              let accessurl = url.entryurl;
              if (
                (encrypt && url.encrypted_entryurl != "") ||
                (accessurl == "" && url.encrypted_entryurl != "")
              ) {
                accessurl = url.encrypted_entryurl;
              }
              let display =
                index == urls.length ||
                url.url.toLowerCase().indexOf(filter_lowercase) != -1;
              if (!display) {
                return null;
              }
              return (
                <tr key={i}>
                  <td>{index}</td>
                  <td>
                    <a href={url.url}>
                      {url.url.length > URL_LENGTH_LIMIT
                        ? url.url.substring(0, URL_LENGTH_LIMIT) + "..."
                        : url.url}
                    </a>
                  </td>
                  <td>
                    <a href={accessurl}>
                      {accessurl.length > URL_LENGTH_LIMIT
                        ? accessurl.substring(0, URL_LENGTH_LIMIT) + "..."
                        : accessurl}
                    </a>
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
                      {copiedIndex == index ? "Copied" : "Copy"}
                    </button>
                    <button
                      title="Delete"
                      onClick={async () => {
                        if (!confirm(`Delete ${url.entryurl}`)) {
                          return;
                        }
                        let newUrls = urls.slice();
                        newUrls.splice(i, 1);
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
                                key + "=" + encodeURIComponent(value);
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
                          setValue("cors", values.cors, option);
                          setValue("nocsp", values.nocsp, option);
                          setValue("debug", values.debug, option);
                          setValue("keytype", values.keytype, option);
                          setValue("scope", values.scope, option);
                          setValue("addon", values.addon, option);
                          setValue("timeout", values.timeout, option);
                          setValue("body", values.body, option);
                          setValue("resbody", values.resbody, option);
                          setValue("url", urlObj.href, option);
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
    if (key == "url") {
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
  console.log("serialize", values);
  return new URLSearchParams(values);
}
