import { describe, it, expect } from 'vitest';
import { escapeHtml, sanitizeHtmlArray } from '../utils/sanitize.js';

describe('sanitize', () => {
  describe('escapeHtml', () => {
    it('escapes HTML special characters', () => {
      expect(escapeHtml('<script>alert("xss")</script>')).toBe(
        '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
      );
    });

    it('handles null and undefined', () => {
      expect(escapeHtml(null)).toBe('');
      expect(escapeHtml(undefined)).toBe('');
    });

    it('handles numbers and booleans', () => {
      expect(escapeHtml(42)).toBe('42');
      expect(escapeHtml(true)).toBe('true');
    });

    it('escapes single quotes', () => {
      expect(escapeHtml("it's")).toBe('it&#x27;s');
    });
  });

  describe('sanitizeHtmlArray', () => {
    it('joins sanitized items with <br>', () => {
      const result = sanitizeHtmlArray(['<b>bold</b>', 'normal']);
      expect(result).toBe('&lt;b&gt;bold&lt;/b&gt;<br>normal');
    });

    it('handles empty array', () => {
      expect(sanitizeHtmlArray([])).toBe('');
    });
  });
});
