import { javaTimeZones } from "./java-time-zones.js";

const dayMs = 86400000;
function utcDate(year, month, day) {
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(0, 0, 0, 0);
  return date;
}
function recurringTransition(rule, year, before, standard) {
  const [month, dom, dow, time, definition, mode] = rule;
  const last = utcDate(year, month + 1, 0).getUTCDate();
  const date = utcDate(year, month, mode === 2 ? (dom > 0 ? 1 : last) : dom);
  if (mode !== 1) {
    const delta = (dow - 1 - date.getUTCDay() + 7) % 7;
    const previous = mode === 4 || (mode === 2 && dom < 0);
    date.setUTCDate(date.getUTCDate() + (previous && delta ? delta - 7 : delta) +
      (mode === 2 ? (dom > 0 ? dom - 1 : dom + 1) * 7 : 0));
  }
  const offset = definition === 2 ? 0 : definition === 1 ? standard : before;
  return date.getTime() / 1000 + time - offset;
}
function zoneState(date, timeZone) {
  const zone = Object.hasOwn(javaTimeZones, timeZone) ? javaTimeZones[timeZone] : null;
  if (!zone) {
    const match = /^GMT([+-])(\d{1,2})(?::?(\d{2}))?$/.exec(timeZone);
    if (match && +match[2] <= 23 && +(match[3] || 0) <= 59) {
      const offset = (match[1] === "-" ? -1 : 1) * (+match[2] * 3600 + +(match[3] || 0) * 60);
      return [offset, "GMT" + match[1] + match[2].padStart(2, "0") + ":" + (match[3] || "00")];
    }
    return [0, "GMT"];
  }
  const seconds = Math.floor(date.getTime() / 1000);
  let [offset, daylight] = zone.b;
  let low = 0, high = zone.t.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (zone.t[middle][0] <= seconds) low = middle + 1;
    else high = middle;
  }
  if (low) [, offset, daylight] = zone.t[low - 1];
  if (zone.c !== null && date.getTime() > zone.c * 1000 && zone.r) {
    const year = date.getUTCFullYear();
    let latest = -Infinity;
    for (let y = year - 1; y <= year + 1; y++) for (const start of [true, false]) {
      const rule = start ? zone.r.s : zone.r.e;
      const instant = recurringTransition(rule, y, zone.r.o + (start ? 0 : zone.r.d), zone.r.o);
      if (instant > latest && instant <= seconds) {
        latest = instant;
        offset = zone.r.o + (start ? zone.r.d : 0); daylight = start ? 1 : 0;
      }
    }
  }
  return [offset, zone.n[daylight]];
}
export function javaLocalDates(date, timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone,
  locale = Intl.DateTimeFormat().resolvedOptions().locale) {
  const [offset, name] = zoneState(date, timeZone);
  const local = new Date(date.getTime() + offset * 1000);
  let year = local.getUTCFullYear(), month = local.getUTCMonth() + 1, day = local.getUTCDate();
  // Java GregorianCalendar switches from the Julian calendar in October 1582.
  if (local.getTime() < -12219292800000) {
    const jdn = Math.floor(local.getTime() / dayMs) + 2440588;
    const c = jdn + 32082, d = Math.floor((4 * c + 3) / 1461);
    const e = c - Math.floor(1461 * d / 4), m = Math.floor((5 * e + 2) / 153);
    day = e - Math.floor((153 * m + 2) / 5) + 1;
    month = m + 3 - 12 * Math.floor(m / 10);
    year = d - 4800 + Math.floor(m / 10);
  }
  const displayYear = year <= 0 ? 1 - year : year;
  const two = value => String(value).padStart(2, "0");
  const weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const calendar = new Intl.DateTimeFormat(locale).resolvedOptions().calendar;
  let numericYear = displayYear + (calendar === "buddhist" ? 543 : 0);
  let numericMonth = month, numericDay = day, yearDigits = 4;
  if (calendar === "japanese") {
    numericYear = local.getUTCFullYear();
    numericMonth = local.getUTCMonth() + 1; numericDay = local.getUTCDate();
    for (const [y, m, d] of [[1868,1,1], [1912,7,30], [1926,12,25], [1989,1,8], [2019,5,1]])
      if (local >= utcDate(y, m, d)) numericYear = local.getUTCFullYear() - y + 1;
    yearDigits = 1;
  }
  const number = (value, digits) => new Intl.NumberFormat(locale, {
    useGrouping: false, minimumIntegerDigits: digits
  }).format(value);
  return {
    dateOnly: (calendar === "japanese" && numericYear === 1 && locale.startsWith("ja") ? "元" : number(numericYear, yearDigits)) +
      "-" + number(numericMonth, 2) + "-" + number(numericDay, 2),
    dateTime: weekdays[local.getUTCDay()] + " " + months[month - 1] + " " + two(day) + " " +
      two(local.getUTCHours()) + ":" + two(local.getUTCMinutes()) + ":" + two(local.getUTCSeconds()) + " " + name + " " + displayYear
  };
}
