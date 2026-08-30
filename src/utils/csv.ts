/**
 * Escape a single CSV cell per RFC 4180.
 * - Wraps in quotes if cell contains comma, quote, or newline.
 * - Doubles existing quotes.
 */
export function escapeCsvCell(cell: string | number | boolean | null | undefined): string {
  if (cell === null || cell === undefined) return '';
  let str = String(cell);
  const needsQuotes = /[",\n\r]/.test(str);
  str = str.replace(/"/g, '""');
  return needsQuotes ? `"${str}"` : str;
}

/**
 * Convert a 2D array to CSV string.
 */
export function toCsv(rows: (string | number | boolean | null | undefined)[][]): string {
  return rows
    .map((row) => row.map(escapeCsvCell).join(','))
    .join('\n');
}
