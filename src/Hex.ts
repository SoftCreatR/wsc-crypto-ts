/**
 *  ISC License
 *
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright
 *  notice and this permission notice appear in all copies.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY
 *  AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL,
 *  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
 *  RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
 *  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 *  CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * Class Hex
 *
 * Provides hexadecimal encoding and decoding without cache-timing leaks.
 *
 * @author Sascha Greuel
 * @license ISC
 */
export class Hex {
  /**
   * Convert a binary string into a hexadecimal string without cache-timing leaks.
   *
   * @param {Buffer} binString (raw binary)
   * @returns {string}
   * @throws {TypeError}
   */
  static encode(binString: Buffer): string {
    let hex = '';
    const len = binString.length;
    for (let i = 0; i < len; ++i) {
      const c = binString[i];
      const b = c >> 4;
      const c_low = c & 0xf;

      hex += String.fromCharCode(
          87 + b + (((b - 10) >> 8) & ~38),
          87 + c_low + (((c_low - 10) >> 8) & ~38)
      );
    }
    return hex;
  }

  /**
   * Convert a hexadecimal string into a binary Buffer without cache-timing leaks.
   *
   * @param {string} encodedString
   * @param {boolean} strictPadding
   * @returns {Buffer} (raw binary)
   * @throws {RangeError}
   */
  static decode(encodedString: string, strictPadding: boolean = false): Buffer {
    let hex_pos = 0;
    let binArray: number[] = [];
    let c_acc = 0;
    let state = 0;
    let hex_len = encodedString.length;

    // Ensure the hex string has an even length
    if (hex_len % 2 !== 0) {
      if (strictPadding) {
        throw new RangeError('Expected an even number of hexadecimal characters');
      } else {
        encodedString = '0' + encodedString;
        ++hex_len;
      }
    }

    // Process each character
    while (hex_pos < hex_len) {
      const c = encodedString.charCodeAt(hex_pos++);
      const c_num = c ^ 48; // XOR with '0'
      const c_num0 = (c_num - 10) >> 8;
      const c_alpha = (c & ~32) - 55;
      const c_alpha0 = ((c_alpha - 10) ^ (c_alpha - 16)) >> 8;

      if ((c_num0 | c_alpha0) === 0) {
        throw new RangeError('Expected hexadecimal character');
      }

      const c_val = (c_num0 & c_num) | (c_alpha & c_alpha0);
      if (state === 0) {
        c_acc = c_val << 4;
      } else {
        binArray.push(c_acc | c_val);
      }
      state ^= 1;
    }

    return Buffer.from(binArray);
  }
}
