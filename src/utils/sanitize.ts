/**
 * Escape HTML special characters to prevent XSS.
 * Replaces <, >, &, ", ' with HTML entities.
 */
export function escapeHtml(input: string | number | boolean | null | undefined): string {
  if (input === null || input === undefined) return '';
  const str = String(input);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Sanitize an array of strings for HTML output.
 */
export function sanitizeHtmlArray(items: unknown[]): string {
  return items
    .map((item) => escapeHtml(item))
    .join('<br>');
}
