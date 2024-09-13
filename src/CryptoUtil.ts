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

import * as crypto from 'crypto';

/**
 * Contains cryptographic helper functions.
 * Features:
 * - Creating secure signatures based on the Keyed-Hash Message Authentication Code algorithm
 *
 * @author Sascha Greuel
 * @license ISC
 */
export class CryptoUtil {
  private signatureSecret: string;

  /**
   * Forbid creation of CryptoUtil objects without a secret.
   *
   * @param {string} signatureSecret The secret used for signing.
   */
  constructor(signatureSecret: string) {
    if (signatureSecret.length < 15) {
      throw new Error('SIGNATURE_SECRET is too short, aborting.');
    }
    this.signatureSecret = signatureSecret;
  }

  /**
   * Signs the given value with the signature secret.
   *
   * @param {Buffer} value The value to be signed.
   * @returns {string} The generated signature as a hex string.
   *
   * @throws {Error} If SIGNATURE_SECRET is too short.
   */
  getSignature(value: Buffer): string {
    if (this.signatureSecret.length < 15) {
      throw new Error('SIGNATURE_SECRET is too short, aborting.');
    }

    return crypto
        .createHmac('sha256', this.signatureSecret)
        .update(value)
        .digest('hex');
  }

  /**
   * Creates a signed (signature + encoded value) string.
   *
   * @param {Buffer} value The value to be signed and encoded.
   * @returns {string} The signed and encoded string.
   */
  createSignedString(value: Buffer): string {
    return this.getSignature(value) + '-' + value.toString('base64');
  }

  /**
   * Extracts the value from a string created with `createSignedString()`
   * after verifying the signature. If the signature is not valid, `null`
   * is returned.
   *
   * Note: The return value MUST be checked with a type-safe `!== null`
   * operation to not confuse a valid, but falsy, value such as `"0"`
   * with an invalid value (`null`).
   *
   * @param {string} signedString The signed string to verify and extract.
   * @returns {Buffer | null} The decoded value if the signature is valid, otherwise null.
   */
  verifySignedString(signedString: string): Buffer | null {
    const parts = signedString.split('-', 2);
    if (parts.length !== 2) {
      return null;
    }
    const [signature, valueBase64] = parts;

    let value: Buffer;
    try {
      value = Buffer.from(valueBase64, 'base64');
    } catch (e) {
      return null;
    }

    if (
        !crypto.timingSafeEqual(
            Buffer.from(signature, 'hex'),
            Buffer.from(this.getSignature(value), 'hex')
        )
    ) {
      return null;
    }

    return value;
  }
}
