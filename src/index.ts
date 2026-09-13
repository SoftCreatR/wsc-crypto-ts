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

import { CryptoUtil, type SignatureSecret } from './CryptoUtil';
import { Hex } from './Hex';

const COOKIE_FORMAT_VERSION = 1;
const SESSION_ID_BYTES = 20;
const SESSION_COOKIE_BYTES = 22;
const COOKIE_TIMESTEP_WINDOW = 24 * 3600;

export interface SessionCookieData {
  sessionId: string;
  timestep: number;
}

function validateTimestamp(timestamp: number): void {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new RangeError('The timestamp must be a non-negative safe integer.');
  }
}

/** Returns WSC's eight-bit, 24-hour cookie timestep. */
export function getCookieTimestep(timestamp = Math.floor(Date.now() / 1000)): number {
  validateTimestamp(timestamp);

  return Math.floor(timestamp / COOKIE_TIMESTEP_WINDOW) & 0xff;
}

/**
 * Creates a WSC 6.2-compatible signed session-cookie value.
 *
 * WSC session IDs are exactly 20 random bytes represented by 40 hexadecimal
 * characters. The bytes, not the UTF-8 representation of those characters,
 * are placed into the packed cookie payload.
 */
export function createSignedSessionCookie(
  sessionId: string,
  secret: SignatureSecret,
  timestamp?: number,
): string {
  const sessionIdBytes = Hex.decode(sessionId, true);

  if (sessionIdBytes.length !== SESSION_ID_BYTES) {
    throw new RangeError('The session ID must contain exactly 40 hexadecimal characters.');
  }

  const packedData = Buffer.alloc(SESSION_COOKIE_BYTES);
  packedData[0] = COOKIE_FORMAT_VERSION;
  sessionIdBytes.copy(packedData, 1);
  packedData[SESSION_COOKIE_BYTES - 1] = getCookieTimestep(timestamp);

  return new CryptoUtil(secret).createSignedString(packedData);
}

/** Verifies and parses a WSC 6.2 session-cookie value. */
export function parseSignedSessionCookie(
  signedCookie: string,
  secret: SignatureSecret,
): SessionCookieData | null {
  const packedData = new CryptoUtil(secret).getValueFromSignedString(signedCookie);

  if (
    packedData === null ||
    packedData.length !== SESSION_COOKIE_BYTES ||
    packedData[0] !== COOKIE_FORMAT_VERSION
  ) {
    return null;
  }

  return {
    sessionId: Hex.encode(packedData.subarray(1, 1 + SESSION_ID_BYTES)),
    timestep: packedData[SESSION_COOKIE_BYTES - 1]!,
  };
}

export { CryptoUtil, Hex };
export type { BinaryValue, SignatureSecret } from './CryptoUtil';
