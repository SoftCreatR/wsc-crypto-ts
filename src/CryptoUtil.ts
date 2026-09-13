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

import { createHmac, timingSafeEqual } from 'node:crypto';

export type BinaryValue = string | Uint8Array;
export type SignatureSecret = string | Uint8Array;

const MINIMUM_SECRET_LENGTH = 15;
const SHA256_HEX_LENGTH = 64;
const BASE64_ALPHABET = /^[A-Za-z0-9+/]*$/u;

function toBuffer(value: BinaryValue): Buffer {
  return typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
}

/**
 * Decodes Base64 with the same non-strict padding behavior as WSC 6.2's
 * `ParagonIE\ConstantTime\Base64::decode()`, while still rejecting characters
 * outside the Base64 alphabet.
 */
function decodeBase64(value: string): Buffer | null {
  const unpadded = value.replace(/=+$/u, '');

  if (!BASE64_ALPHABET.test(unpadded)) {
    return null;
  }

  return Buffer.from(unpadded, 'base64');
}

/** Creates and verifies WSC-compatible HMAC-SHA-256 signed strings. */
export class CryptoUtil {
  readonly #signatureSecret: Buffer;

  constructor(signatureSecret: SignatureSecret) {
    this.#signatureSecret = toBuffer(signatureSecret);

    // WSC checks the byte length (`mb_strlen(..., '8bit')`), not the number of
    // Unicode code points or UTF-16 code units.
    if (this.#signatureSecret.length < MINIMUM_SECRET_LENGTH) {
      throw new Error('SIGNATURE_SECRET is too short, aborting.');
    }
  }

  /** Returns the lowercase hexadecimal HMAC-SHA-256 signature for `value`. */
  getSignature(value: BinaryValue): string {
    return createHmac('sha256', this.#signatureSecret).update(toBuffer(value)).digest('hex');
  }

  /** Returns the WSC wire format: `<hex signature>-<padded Base64 value>`. */
  createSignedString(value: BinaryValue): string {
    const binaryValue = toBuffer(value);

    return `${this.getSignature(binaryValue)}-${binaryValue.toString('base64')}`;
  }

  /**
   * Verifies and extracts a value created by `createSignedString()`.
   *
   * Malformed input and invalid signatures return `null`; they never cause
   * `timingSafeEqual()` to throw because of buffers with different lengths.
   */
  getValueFromSignedString(signedString: string): Buffer | null {
    const separator = signedString.indexOf('-');

    if (separator === -1) {
      return null;
    }

    const signature = signedString.slice(0, separator);
    const value = decodeBase64(signedString.slice(separator + 1));

    if (value === null) {
      return null;
    }

    const expectedSignature = Buffer.from(this.getSignature(value), 'ascii');
    const providedSignature = Buffer.from(signature, 'utf8');

    if (
      providedSignature.length !== SHA256_HEX_LENGTH ||
      !timingSafeEqual(providedSignature, expectedSignature)
    ) {
      return null;
    }

    return value;
  }
}
