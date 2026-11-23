// Small helpers for showing values on screen

const dateTime = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "medium",
});

export function formatTime(iso: string): string {
  return dateTime.format(new Date(iso));
}

export function formatNumber(value: number): string {
  return value.toLocaleString();
}

/** "input_blocked" -> "input blocked" */
export function words(value: string): string {
  return value.replaceAll("_", " ");
}

/** The time `hours` ago, in the form the API wants (with a timezone). */
export function hoursAgo(hours: number, now: Date = new Date()): string {
  return new Date(now.getTime() - hours * 3_600_000).toISOString();
}
