'use strict';

const assert = require('node:assert/strict');
const { createHmac } = require('node:crypto');
const { test } = require('node:test');

const {
  createSignedSessionCookie,
  CryptoUtil,
  getCookieTimestep,
  Hex,
  parseSignedSessionCookie,
} = require('../dist');

const SECRET = '0123456789abcdef';
const SESSION_ID = '0123456789abcdef0123456789abcdef01234567';
const TIMESTAMP = 1_726_185_600;
const WSC_SESSION_COOKIE =
  '4bebd982a04a68f40cc2ef6bdd1e3a370cb8985d17d251aa3498f9a2ba0a05a8-AQEjRWeJq83vASNFZ4mrze8BI0VnCw==';

test('creates WSC-compatible HMAC signed strings', () => {
  const cryptoUtil = new CryptoUtil(SECRET);
  const value = Buffer.from([0x00, 0x01, 0xfe, 0xff]);
  const expectedSignature = createHmac('sha256', SECRET).update(value).digest('hex');

  assert.equal(cryptoUtil.getSignature(value), expectedSignature);
  assert.equal(cryptoUtil.createSignedString(value), `${expectedSignature}-AAH+/w==`);
  assert.deepEqual(
    cryptoUtil.getValueFromSignedString(`${expectedSignature}-AAH+/w==`),
    value,
  );
});

test('accepts string and Uint8Array inputs without runtime dependencies', () => {
  const cryptoUtil = new CryptoUtil(new TextEncoder().encode(SECRET));
  const signedString = cryptoUtil.createSignedString('WoltLab');

  assert.equal(cryptoUtil.getValueFromSignedString(signedString)?.toString(), 'WoltLab');
});

test('measures signature-secret length in bytes like WSC', () => {
  assert.throws(() => new CryptoUtil('12345678901234'), /SIGNATURE_SECRET is too short/u);
  assert.doesNotThrow(() => new CryptoUtil('🔐🔐🔐🔐'));
});

test('returns null instead of throwing for malformed signatures', () => {
  const cryptoUtil = new CryptoUtil(SECRET);

  assert.equal(cryptoUtil.getValueFromSignedString('notSigned'), null);
  assert.equal(cryptoUtil.getValueFromSignedString('not-signed'), null);
  assert.equal(cryptoUtil.getValueFromSignedString(`00-${Buffer.from('value').toString('base64')}`), null);
  assert.equal(
    cryptoUtil.getValueFromSignedString(`${'0'.repeat(64)}-${Buffer.from('value').toString('base64')}`),
    null,
  );
  assert.equal(cryptoUtil.getValueFromSignedString(`${'0'.repeat(64)}-@@@`), null);
  assert.equal(cryptoUtil.getValueFromSignedString(`${'0'.repeat(64)}-dm=FsdWU=`), null);
  assert.equal(cryptoUtil.getValueFromSignedString(`${'0'.repeat(64)}-dmFsdWU=-extra`), null);
});

test('matches WSC non-strict trailing Base64 padding behavior', () => {
  const cryptoUtil = new CryptoUtil(SECRET);
  const signedString = cryptoUtil.createSignedString('x');
  const [signature] = signedString.split('-', 1);

  assert.equal(cryptoUtil.getValueFromSignedString(`${signature}-eA`)?.toString(), 'x');
  assert.equal(cryptoUtil.getValueFromSignedString(`${signature}-eA======`)?.toString(), 'x');

  const emptySignedString = cryptoUtil.createSignedString(Buffer.alloc(0));
  assert.deepEqual(cryptoUtil.getValueFromSignedString(emptySignedString), Buffer.alloc(0));
});

test('hex encoding and decoding matches all byte values', () => {
  const bytes = Buffer.from(Array.from({ length: 256 }, (_, value) => value));

  assert.equal(Hex.encode(bytes), bytes.toString('hex'));
  assert.equal(Hex.encodeUpper(bytes), bytes.toString('hex').toUpperCase());
  assert.deepEqual(Hex.decode(bytes.toString('hex')), bytes);
  assert.deepEqual(Hex.decode(bytes.toString('hex').toUpperCase()), bytes);
});

test('hex decoding matches WSC padding and validation behavior', () => {
  assert.deepEqual(Hex.decode('abc'), Buffer.from([0x0a, 0xbc]));
  assert.throws(() => Hex.decode('abc', true), /even number/u);
  assert.throws(() => Hex.decode('xy'), /hexadecimal character/u);
  assert.throws(() => Hex.decode('１２'), /hexadecimal character/u);

  for (let code = 0; code <= 0x7f; code += 1) {
    const character = String.fromCharCode(code);
    const isHexadecimal = /^[0-9A-Fa-f]$/u.test(character);

    if (isHexadecimal) {
      assert.doesNotThrow(() => Hex.decode(character.repeat(2)));
    } else {
      assert.throws(() => Hex.decode(character.repeat(2)), RangeError);
    }
  }
});

test('creates the exact WSC 6.2 session-cookie fixture', () => {
  assert.equal(getCookieTimestep(TIMESTAMP), 11);
  assert.equal(createSignedSessionCookie(SESSION_ID, SECRET, TIMESTAMP), WSC_SESSION_COOKIE);
  assert.deepEqual(parseSignedSessionCookie(WSC_SESSION_COOKIE, SECRET), {
    sessionId: SESSION_ID,
    timestep: 11,
  });
});

test('uses the current time when no timestamp is supplied', () => {
  assert.ok(getCookieTimestep() >= 0 && getCookieTimestep() <= 0xff);
});

test('session helpers reject invalid input and payload versions', () => {
  assert.throws(
    () => createSignedSessionCookie('your-session-id', SECRET, TIMESTAMP),
    /hexadecimal character/u,
  );
  assert.throws(
    () => createSignedSessionCookie('00', SECRET, TIMESTAMP),
    /exactly 40 hexadecimal characters/u,
  );
  assert.throws(() => getCookieTimestep(-1), /non-negative safe integer/u);
  assert.throws(() => getCookieTimestep(Number.NaN), /non-negative safe integer/u);

  const unknownVersion = Buffer.alloc(22);
  unknownVersion[0] = 2;
  const signedString = new CryptoUtil(SECRET).createSignedString(unknownVersion);
  assert.equal(parseSignedSessionCookie(signedString, SECRET), null);
  assert.equal(
    parseSignedSessionCookie(new CryptoUtil(SECRET).createSignedString('too short'), SECRET),
    null,
  );
});
