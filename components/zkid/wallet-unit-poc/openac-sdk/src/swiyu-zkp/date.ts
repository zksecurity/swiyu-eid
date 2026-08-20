const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Validate the exact date domain implemented by `IsoDate1900To2199`. */
export function parseSwiyuIsoDate(value: string, label: string): bigint {
  const match = ISO_DATE.exec(value);
  if (!match) throw new Error(`${label} must be YYYY-MM-DD`);
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (year < 1900 || year > 2199) {
    throw new Error(`${label} year must be in 1900..2199`);
  }
  if (month < 1 || month > 12) throw new Error(`${label} has an invalid month`);
  const leap = year % 4 === 0 && year !== 1900 && year !== 2100;
  const monthLengths = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > monthLengths[month - 1]!) {
    throw new Error(`${label} has an invalid day`);
  }
  return BigInt(year * 10_000 + month * 100 + day);
}
