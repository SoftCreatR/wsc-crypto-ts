# Changelog

## 2.0.0

- Fix WSC session-cookie generation by hex-decoding the session ID before packing it.
- Return `null` for malformed or wrong-length signatures instead of allowing `timingSafeEqual()` to throw.
- Reject non-Base64 input that Node.js would otherwise decode permissively.
- Match WSC's byte-based minimum secret length.
- Replace the v1 API with `getValueFromSignedString()`, `createSignedSessionCookie()`, and `parseSignedSessionCookie()`.
- Add uppercase hexadecimal encoding and broader binary input types.
- Require Node.js 22 and publish modern declarations, source maps, and package exports.
- Replace the demonstration script with an automated compatibility and regression suite.
