/**
 * @param ts unix timestamp in seconds
 * @returns date string in "yyyy-MM-dd" format. if ts <= 0, returns empty string.
 */
export function format_date(ts: number): string {
  if (ts <= 0) {
    return "";
  }
  let date = new Date(ts * 1000);
  // iso string: '2024-07-30T02:14:15.955Z'
  return date.toISOString().substring(0, 10);
}

/**
 * Generate a cryptographically strong password of format /[a-zA-Z0-9]{length}/
 */
export function generatePassword(length: number) {
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
