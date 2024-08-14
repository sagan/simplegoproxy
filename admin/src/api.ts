interface Generate {
  url: string;
  entryurl: string;
  sign: string;
}

interface GenerateRequest {
  url: string;
  publicurl: string;
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
  let res = await fetch(window.__APIURL__, {
    method: "POST",
    mode: "cors",
    cache: "no-cache",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: data.toString(),
  });
  if (res.status != 200) {
    throw new Error(`status=${res.status}`);
  }
  let resdata = (await res.json()) as T;
  return resdata;
}

export async function fetchGenerate(req: GenerateRequest) {
  return await fetchApi<Generate>({ func: "generate", ...req });
}

export type { Generate, GenerateRequest };