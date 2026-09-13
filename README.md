# wsc-crypto-ts

Dependency-free TypeScript helpers for cryptographic wire formats used by WoltLab Suite Core 6.2.

The package provides:

- HMAC-SHA-256 signed strings compatible with `wcf\util\CryptoUtil`
- WSC 6.2 session-cookie creation and parsing
- constant-time-style hexadecimal encoding and decoding
- CommonJS output and TypeScript declarations

Node.js 22 or newer is required. The package has no runtime dependencies.

## Installation

```bash
npm install wsc-crypto-ts
```

## Signed values

```typescript
import { CryptoUtil } from 'wsc-crypto-ts';

const cryptoUtil = new CryptoUtil(process.env.SIGNATURE_SECRET!);
const signedValue = cryptoUtil.createSignedString('example');
const value = cryptoUtil.getValueFromSignedString(signedValue);

if (value !== null) {
  console.log(value.toString('utf8'));
}
```

Secrets must contain at least 15 bytes, matching WSC 6.2. Values and secrets may be supplied as strings or `Uint8Array` instances. Strings are encoded as UTF-8.

## Session cookies

```typescript
import {
  createSignedSessionCookie,
  parseSignedSessionCookie,
} from 'wsc-crypto-ts';

const sessionId = '0123456789abcdef0123456789abcdef01234567';
const secret = process.env.SIGNATURE_SECRET!;

const cookieValue = createSignedSessionCookie(sessionId, secret);
const session = parseSignedSessionCookie(cookieValue, secret);

if (session !== null) {
  console.log(session.sessionId, session.timestep);
}
```

A WSC session ID is exactly 20 bytes represented by 40 hexadecimal characters. Version 1.x incorrectly packed the hexadecimal characters themselves and therefore produced session-cookie values that were incompatible with WSC. Version 2.x decodes the session ID before creating WSC's 22-byte payload.

For deterministic tests, pass a Unix timestamp as the third argument to `createSignedSessionCookie()`.

## Hexadecimal values

```typescript
import { Hex } from 'wsc-crypto-ts';

const bytes = Hex.decode('48656c6c6f');

console.log(Hex.encode(bytes));      // 48656c6c6f
console.log(Hex.encodeUpper(bytes)); // 48656C6C6F
```

By default, `Hex.decode()` matches WSC's handling of odd-length input by adding a leading zero. Pass `true` as the second argument to require an even number of characters.

## Development

```bash
npm ci --no-audit --no-fund
npm test
npm run test:coverage
npm pack --dry-run
```

The test suite includes a session-cookie fixture generated from the WSC 6.2 packing and signing algorithm, malformed-input coverage, and all 256 byte values for hexadecimal round trips.

## License

[ISC](LICENSE.md)
