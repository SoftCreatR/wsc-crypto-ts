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

import { CryptoUtil } from './CryptoUtil';
import { Hex } from './Hex';

/**
 * Contains helper functions related to timestamp management for cookie timesteps.
 *
 * @author Sascha Greuel
 * @license ISC
 */

let customTimestamp: number | null = null;

/**
 * Sets a custom Unix timestamp for testing purposes.
 * @param {number} timestamp Unix timestamp in seconds.
 */
export function setCustomTimestamp(timestamp: number): void {
  customTimestamp = timestamp;
}

/**
 * Clears the custom Unix timestamp, reverting to the current time.
 */
export function clearCustomTimestamp(): void {
  customTimestamp = null;
}

/**
 * Returns the current Unix timestamp in seconds, or a custom one if set.
 * @returns {number} Unix timestamp in seconds.
 */
function getCurrentTimestamp(): number {
  return customTimestamp ?? Math.floor(Date.now() / 1000);
}

/**
 * Calculates a cookie timestep value based on the current or custom time.
 * @returns {number} The cookie timestep.
 */
export function getCookieTimestep(): number {
  const window = 24 * 3600; // 24 hours in seconds
  const now = getCurrentTimestamp(); // Unix timestamp in seconds

  return Math.floor(now / window) & 0xff; // Time window calculation
}

/**
 * Creates a signed string based on session ID.
 * Mimics the behavior of PHP's pack('CA20C', ...) with a normal string.
 *
 * @param {string} sessionID The session ID as a normal string.
 * @param {string} secret The secret key used for signing.
 * @returns {string} The signed string.
 */
export function createSignedStringForSession(
    sessionID: string,
    secret: string
): string {
  // Convert the sessionID to a Buffer using UTF-8 encoding
  let sessionIDBuffer = Buffer.from(sessionID, 'utf8');

  // Pad the sessionID with spaces (0x20) to 20 bytes, similar to PHP's pack('A20')
  if (sessionIDBuffer.length < 20) {
    const paddingLength = 20 - sessionIDBuffer.length;
    const padding = Buffer.alloc(paddingLength, 0x20); // Fill with spaces (0x20)
    sessionIDBuffer = Buffer.concat([sessionIDBuffer, padding]);
  } else if (sessionIDBuffer.length > 20) {
    // Truncate if longer than 20 bytes
    sessionIDBuffer = sessionIDBuffer.subarray(0, 20);
  }

  // Build the packed data
  const packedData = Buffer.concat([
    Buffer.from([1]), // Pack the number 1 (like 'C' in PHP pack)
    sessionIDBuffer, // The 20-byte session ID, padded with spaces
    Buffer.from([getCookieTimestep()]), // The timestep
  ]);

  const cryptoUtil = new CryptoUtil(secret);
  return cryptoUtil.createSignedString(packedData);
}

export { CryptoUtil, Hex };
