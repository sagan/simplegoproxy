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
