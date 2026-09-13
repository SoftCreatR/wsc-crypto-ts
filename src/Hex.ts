/**
 * ISC License
 *
 * Copyright (c) 2024-2026 Sascha Greuel
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/** Hexadecimal encoding compatible with WSC 6.2's constant-time encoder. */
export abstract class Hex {
  /** Encodes bytes as lowercase hexadecimal. */
  static encode(binary: Uint8Array): string {
    let hex = '';

    for (const byte of binary) {
      const high = byte >> 4;
      const low = byte & 0x0f;

      hex += String.fromCharCode(
        87 + high + (((high - 10) >> 8) & ~38),
        87 + low + (((low - 10) >> 8) & ~38),
      );
    }

    return hex;
  }

  /** Encodes bytes as uppercase hexadecimal. */
  static encodeUpper(binary: Uint8Array): string {
    let hex = '';

    for (const byte of binary) {
      const high = byte >> 4;
      const low = byte & 0x0f;

      hex += String.fromCharCode(
        55 + high + (((high - 10) >> 8) & ~6),
        55 + low + (((low - 10) >> 8) & ~6),
      );
    }

    return hex;
  }

  /**
   * Decodes hexadecimal bytes. Odd-length values receive a leading zero unless
   * `strictPadding` is enabled, matching WSC 6.2.
   */
  static decode(encodedString: string, strictPadding = false): Buffer {
    let hex = encodedString;

    if ((hex.length & 1) !== 0) {
      if (strictPadding) {
        throw new RangeError('Expected an even number of hexadecimal characters');
      }

      hex = `0${hex}`;
    }

    const binary = Buffer.alloc(hex.length / 2);
    let accumulator = 0;
    let state = 0;
    let outputPosition = 0;

    for (let position = 0; position < hex.length; position += 1) {
      const character = hex.charCodeAt(position);

      // The bit masks below operate on bytes in the upstream algorithm. Reject
      // non-ASCII code units explicitly before applying the same conversion.
      if (character > 0x7f) {
        throw new RangeError('Expected hexadecimal character');
      }

      const numeric = character ^ 48;
      const numericMask = (numeric - 10) >> 8;
      const alpha = (character & ~32) - 55;
      const alphaMask = ((alpha - 10) ^ (alpha - 16)) >> 8;

      if ((numericMask | alphaMask) === 0) {
        throw new RangeError('Expected hexadecimal character');
      }

      const value = (numericMask & numeric) | (alphaMask & alpha);

      if (state === 0) {
        accumulator = value * 16;
      } else {
        binary[outputPosition] = accumulator | value;
        outputPosition += 1;
      }
      state ^= 1;
    }

    return binary;
  }
}
