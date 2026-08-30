import { describe, it, expect } from 'vitest';
import { escapeCsvCell, toCsv } from '../utils/csv.js';

describe('csv', () => {
  describe('escapeCsvCell', () => {
    it('wraps cells with commas in quotes', () => {
      expect(escapeCsvCell('hello, world')).toBe('"hello, world"');
    });

    it('doubles quotes inside cells', () => {
      expect(escapeCsvCell('say "hello"')).toBe('"say ""hello"""');
    });

    it('handles newlines', () => {
      expect(escapeCsvCell('line1\nline2')).toBe('"line1\nline2"');
    });

    it('handles null and undefined', () => {
      expect(escapeCsvCell(null)).toBe('');
      expect(escapeCsvCell(undefined)).toBe('');
    });
  });

  describe('toCsv', () => {
    it('converts rows to CSV format', () => {
      const rows = [
        ['Name', 'Status'],
        ['Alice', 'Active'],
        ['Bob, Jr.', 'Inactive'],
      ];
      expect(toCsv(rows)).toBe('Name,Status\nAlice,Active\n"Bob, Jr.",Inactive');
    });
  });
});
