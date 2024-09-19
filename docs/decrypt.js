const { parseArgs } = require("util");

// node decrypt.js --url "http://localhost:8380/xxx" --password abc --localsign --publickey

// Fetch a Simplegoproxy entrypoint url with encrypted response and decrypt it.
// Assume Simplegoproxy server is using default "_sgp_" prefix.
// Should works in recent node.js & browsers.
(async function main() {
  const {
    values: { url, suburl, password, localsign, publickey, nodecrypt },
  } = parseArgs({
    options: {
      url: {
        type: "string",
      },
      suburl: {
        type: "string",
      },
      password: {
        type: "string",
      },
      localsign: {
        type: "boolean",
      },
      publickey: {
        type: "boolean",
      },
      nodecrypt: {
        type: "boolean",
      },
    },
  });
  let plaintext = await fetchAndDecrypt({
    url,
    suburl,
    password,
    localsign,
    publickey,
    nodecrypt,
  });
  console.log("plaintext\n", plaintext);
})();

/**
 * Generate a cryptographically strong random string of format /[a-zA-Z0-9]{length}/
 */
function generateRandomString(length) {
  if (length <= 0) {
    return "";
  }
  let chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let password = "";
  let max = Math.floor(65535 / chars.length) * chars.length;
  const array = new Uint16Array(length * 2);
  while (true) {
    crypto.getRandomValues(array);
    for (let i = 0; i < array.length; i++) {
      // By taking only the numbers up to a multiple of char space size and discarding others,
      // we expect a uniform distribution of all possible chars.
      if (array[i] < max) {
        password += chars[array[i] % chars.length];
      }
    }
    if (password.length >= length) {
      break;
    }
  }
  return password;
}

// https://developer.mozilla.org/en-US/docs/Glossary/Base64
function base64ToBytes(base64) {
  const binString = atob(base64);
  return Uint8Array.from(binString, (m) => m.codePointAt(0));
}

function bytesToBase64(bytes) {
  const binString = Array.from(bytes, (byte) =>
    String.fromCodePoint(byte)
  ).join("");
  return btoa(binString);
}

/**
 * hex string => Uint8Array
 */
function fromHexString(hexString) {
  return new Uint8Array(
    hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
  );
}

/**
 * Uint8Array / ArrayBuffer => hex string
 */
function toHexString(arr) {
  if (arr instanceof ArrayBuffer) {
    arr = new Uint8Array(arr);
  }
  return Array.from(arr, (i) => i.toString(16).padStart(2, "0")).join("");
}

/**
 * Fetch a encrypted url and decrypt it.
 * @param url String. The entrypoint url of Simplegoproxy with "response encryption" enabled.
 * @param suburl String. The suburl, which will be concated to url.
 * @param password String. The response encryption password. The symmetric AES-256-GCM key is derived from password.
 * @param publickey Bool. If true, will generate a ephemeral X25519 key and do ECDH with server.
 *  In this case, the symmetric AES-256-GCM key is derived from both the password and the ECDH.
 *  This will provide forward secrecy, but will be much slower.
 * @param nodecrypt Bool. If true, the response is not encrypted.
 *  This flag should be set when and only when the unecrypted form or url has encmode&(64) != 0.
 * @param localsign Bool. If true, do local signing of suburl using password. It will prevent replay attacks.
 *  This flag should be set when and only when the unecrypted form or url has encmode&(32 || 64) != 0.
 * @param prefix String. The modification parameter prefix. Default is "_sgp_".
 * @returns Promise of string. The decrypted response plaintext.
 */
async function fetchAndDecrypt({
  url = "",
  suburl = "",
  password = "",
  localsign = false,
  publickey = false,
  nodecrypt = false,
  prefix = "_sgp_",
} = {}) {
  if (url == "" || password == "") {
    throw new Error("url must be set");
  }
  if (suburl != "") {
    if (!url.endsWith("/")) {
      url += "/";
    }
    if (suburl.startsWith("/")) {
      suburl = suburl.substring(1);
    }
  }
  let params = new URLSearchParams();
  let salt = generateRandomString(32);
  params.set(prefix + "salt", salt);

  let privatekey;
  if (publickey) {
    let keypair = await crypto.subtle.generateKey(
      {
        name: "X25519",
      },
      true,
      ["deriveKey"]
    );
    let publicKeyData = await crypto.subtle.exportKey("raw", keypair.publicKey);
    privatekey = keypair.privateKey;
    params.set(prefix + "publickey", toHexString(publicKeyData));
  }

  if (localsign) {
    let index = suburl.indexOf("?");
    if (index != -1) {
      let queryparams = new URLSearchParams(suburl.substring(index));
      suburl = suburl.substring(0, index);
      for (let [key, value] of queryparams) {
        params.append(key, value);
      }
    }
    // '2024-09-19T04:40:08.934Z'
    let ts = new Date().toISOString().substring(0, 19);
    ts = ts.replace("T", "_");
    ts = ts.replace(/:/g, "-");
    ts += generateRandomString(20); // "2024-09-19_04-40-08XXX..."
    params.set(prefix + "nonce", ts);
    params.sort();
    let signurl = suburl + "?" + params.toString();
    let localsignkey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      {
        name: "HMAC",
        hash: { name: "SHA-256" },
      },
      false,
      ["sign", "verify"]
    );
    let localsign = await crypto.subtle.sign(
      "HMAC",
      localsignkey,
      new TextEncoder().encode(signurl)
    );
    params.set(prefix + "localsign", toHexString(localsign));
  }

  url += suburl;
  if (url.indexOf("?") == -1) {
    url += "?";
  } else if (!url.endsWith("?") && !url.endsWith("&")) {
    url += "&";
  }
  url += params.toString();

  const keymaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );
  let key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: 1000000,
      hash: "SHA-256",
    },
    keymaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  console.log("fetch", url);
  const res = await fetch(url);
  if (res.status != 200) {
    throw new Error(`Server return status ${res.status}`);
  }
  if (nodecrypt) {
    return await res.text();
  }
  let cipherdata = new Uint8Array();
  let restype = res.headers.get("Content-Type");
  if (restype == "application/octet-stream") {
    cipherdata = new Uint8Array(await res.arrayBuffer());
  } else if (restype == "text/plain; charset=utf-8") {
    cipherdata = base64ToBytes(await res.text());
  } else {
    throw new Error(`Invalid response content type ${restype}`);
  }

  if (privatekey) {
    let remotePublickey = await crypto.subtle.importKey(
      "raw",
      base64ToBytes(res.headers.get("X-Encryption-Publickey")),
      { name: "X25519" },
      true,
      []
    );
    // Do X25519 ECDH, derive secret from local private key and remote (server) public key.
    let secret = await crypto.subtle.deriveKey(
      {
        name: "X25519",
        public: remotePublickey,
      },
      privatekey,
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"]
    );

    // xor key with ECDH secret to get the effective key.
    let keyData = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    let secretData = new Uint8Array(
      await crypto.subtle.exportKey("raw", secret)
    );
    for (let i = 0; i < keyData.length; i++) {
      keyData[i] ^= secretData[i];
    }
    key = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  const alg = { name: "AES-GCM", iv: cipherdata.slice(0, 12) };
  const plaindata = await crypto.subtle.decrypt(alg, key, cipherdata.slice(12));
  return new TextDecoder().decode(plaindata);
}
