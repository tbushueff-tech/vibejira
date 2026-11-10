import { javaZoneNames } from "./java-zone-names.js";

// The browser's local zone is Java's equivalent of the default JVM timezone.
// An explicit IANA zone lets interoperability tests use the same environment.
export function javaLocalDates(date, timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-US-u-ca-gregory-nu-latn", {
    timeZone, weekday: "short", year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
    timeZoneName: "longOffset"
  }).formatToParts(date).map(({ type, value }) => [type, value]));
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const month = String(months.indexOf(parts.month) + 1).padStart(2, "0");
  const offset = parts.timeZoneName.match(/GMT([+-])(\d{2}):(\d{2})(?::(\d{2}))?/);
  const seconds = offset ? (offset[1] === "-" ? -1 : 1) *
    (+offset[2] * 3600 + +offset[3] * 60 + +(offset[4] || 0)) : 0;
  const names = javaZoneNames[timeZone];
  const zoneName = names ? names[seconds === names[0] ? 1 : 2] :
    (seconds === 0 ? "GMT" : parts.timeZoneName);
  const year = parts.year.padStart(4, "0");
  return {
    dateOnly: year + "-" + month + "-" + parts.day,
    dateTime: `${parts.weekday} ${parts.month} ${parts.day} ${parts.hour}:${parts.minute}:${parts.second} ${zoneName} ${year}`
  };
}
