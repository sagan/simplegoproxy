// Fetch a Simplegoproxy entrypoint url with encrypted response and decrypt it.
// Assume Simplegoproxy server is using default "_sgp_" prefix.
// Should works in recent node.js & browsers.
(async function main() {
  let url = "http://localhost:8380/abcdefghijklmnopqrstuvwxyz";
  let password = "abc";
  let usePublickey = true;
  let plaintext = await fetchAndDecrypt(url, password, usePublickey);
  console.log("plaintext:", plaintext);
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

// hex string => Uint8Array
function fromHexString(hexString) {
  return new Uint8Array(
    hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
  );
}

// Uint8Array / ArrayBuffer => hex string
function toHexString(arr) {
  if (arr instanceof ArrayBuffer) {
    arr = new Uint8Array(arr);
  }
  return Array.from(arr, (i) => i.toString(16).padStart(2, "0")).join("");
}

/**
 * Fetch a encrypted url and decrypt it.
 * @param url String. The entrypoint url of Simplegoproxy with "response encryption" enabled.
 * @param password String. The response encryption password. The symmetric AES-256-GCM key is derived from password.
 * @param usePublickey Bool. If true, will generate a ephemeral X25519 key and do ECDH with server.
 * In this case, the symmetric AES-256-GCM key is derived from both the password and the ECDH.
 * This will provide forward secrecy, but will be much slower.
 * @returns Promise of string. The decrypted response plaintext.
 */
async function fetchAndDecrypt(url, password, usePublickey) {
  if (url.indexOf("?") == -1) {
    url += "?";
  } else if (!url.endsWith("?") && !url.endsWith("&")) {
    url += "&";
  }
  let salt = generateRandomString(32);
  url += "_sgp_salt=" + salt + "&";

  let privatekey;
  if (usePublickey) {
    let keypair = await crypto.subtle.generateKey(
      {
        name: "X25519",
      },
      true,
      ["deriveKey"]
    );
    let publicKeyData = await crypto.subtle.exportKey("raw", keypair.publicKey);
    url += "_sgp_publickey=" + toHexString(publicKeyData) + "&";
    privatekey = keypair.privateKey;
  }

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

  const res = await fetch(url);
  const ciphertext = await res.text();
  const cipherdata = base64ToBytes(ciphertext);

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
