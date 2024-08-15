import React, { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { useSearchParams } from "react-router-dom";
import { useLocalStorage } from "@rehooks/local-storage";
import { Generate, GenerateRequest, fetchGenerate } from "./api.js";

interface InputForm {
  url: string;
  keytype: string;
  cors: boolean;
  nocsp: boolean;
  fdua: boolean;
  fdauth: boolean;
  addon: string;
  scope: string;
  timeout: number;
}

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
  return (
    <>
      <form
        onSubmit={handleSubmit(async (data: InputForm) => {
          setSearchParams(serializeInputForm(data));

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
            {...register("url")}
          />
          <button type="submit">Generate</button>
          <button type="reset">Reset</button>
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
        </p>
      </form>
      <div className="flex-1 overflow-auto">
        <h2 className="flex">
          <span className="flex-1">Generated Urls (Stored locally)</span>
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
              return (
                <tr key={i}>
                  <td>{index}</td>
                  <td>
                    <a href={url.url}>{url.url}</a>
                  </td>
                  <td>
                    <a href={url.entryurl}>{url.entryurl}</a>
                  </td>
                  <td>
                    <button
                      onClick={async () => {
                        try {
                          navigator.clipboard.writeText(url.entryurl);
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
  let { url, fdua, fdauth, addon, ...others } = data;
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

function serializeInputForm(data: InputForm): URLSearchParams {
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
  console.log("serialize", values);
  return new URLSearchParams(values);
}
