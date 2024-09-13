const {
  createSignedStringForSession,
  CryptoUtil,
} = require("./dist/index");

// Set the signature secret
const secret = 'your-signature-secret';

// Session ID as a normal string
const sessionID = 'your-session-id';

// Create the signed string
const signedString = createSignedStringForSession(sessionID, secret);
console.log('Signed String:', signedString);

// Initialize CryptoUtil with the secret
const cryptoUtil = new CryptoUtil(secret);

// Verify and decode the signed string
const decodedValue = cryptoUtil.verifySignedString(signedString);

if (decodedValue !== null) {
  console.log('Decoded Value:', decodedValue.toString('utf8'));
} else {
  console.error('Invalid signature!');
}
