let apiUrl = window.__ROOT__ + "admin/api";

interface Generate {
  url: string;
  entryurl: string;
  sign: string;
}

export async function fetchApi<T>(params: { [key: string]: string }) {
  var data = new URLSearchParams();
  for (let [key, value] of Object.entries(params)) {
    if (Array.isArray(value)) {
      for (let v of value) {
        data.append(key, v);
      }
    } else {
      data.set(key, value);
    }
  }
  let res = await fetch(apiUrl + "?" + data.toString(), {
    method: "GET",
    mode: "cors",
    cache: "no-cache",
  });
  if (res.status != 200) {
    throw new Error(`status=${res.status}`);
  }
  let resdata = (await res.json()) as T;
  return resdata;
}

export async function fetchGenerate() {
  return await fetchApi<Generate>({ func: "generate" });
}

export type { Generate };
