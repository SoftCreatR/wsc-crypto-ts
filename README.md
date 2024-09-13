# wsc-crypto-ts

PoC of cryptographic utility functions for WoltLab Suite Core, implemented in TypeScript.

## Overview

This project provides cryptographic helper functions, including:

- Creating secure signatures based on the Keyed-Hash Message Authentication Code (HMAC) algorithm.
- Hexadecimal encoding and decoding without cache-timing leaks.

## Installation

```bash
npm install wsc-crypto-ts
```

## Usage

### Creating a Signed String

```typescript
import { createSignedStringForSession } from 'wsc-crypto-ts';

// Your session ID and secret
const sessionID = 'your-session-id';
const secret = 'your-secret-key';

// Create a signed string
const signedString = createSignedStringForSession(sessionID, secret);

console.log('Signed String:', signedString);
```

### Verifying a Signed String

```typescript
import { CryptoUtil } from 'wsc-crypto-ts';

// Initialize CryptoUtil with your secret
const cryptoUtil = new CryptoUtil(secret);

// Verify and decode the signed string
const decodedValue = cryptoUtil.verifySignedString(signedString);

if (decodedValue !== null) {
  console.log('Decoded Value:', decodedValue.toString('utf8'));
} else {
  console.error('Invalid signature!');
}
```

## License

This project is licensed under the ISC License. See the [LICENSE](LICENSE.md) file for details.

## Author

- **Sascha Greuel**
- **Email:** [hello@1-2.dev](mailto:hello@1-2.dev)
- **GitHub:** [SoftCreatR](https://github.com/SoftCreatR)
