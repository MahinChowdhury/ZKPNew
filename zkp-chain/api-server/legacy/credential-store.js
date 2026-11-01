// ============================================================
// credential-store.js — Server-side encrypted credential store
// Stores SNARK credentials (poseidonFaceHash, secretKey, commitment)
// encrypted with the user's password, keyed by nidHash.
//
// The server CANNOT read these without the user's password,
// preserving the same security model as the QR-only approach.
// ============================================================

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const CREDENTIALS_DIR = path.join(__dirname, "credentials");

// Ensure the credentials directory exists
if (!fs.existsSync(CREDENTIALS_DIR)) {
  fs.mkdirSync(CREDENTIALS_DIR, { recursive: true });
}

/**
 * Derive AES-256 key from password + salt using PBKDF2
 * (Same parameters as the QR encryption)
 */
function deriveKeyFromPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");
}

/**
 * Encrypt data with AES-256-CBC + PBKDF2
 * Uses the same encryption scheme as the QR payload.
 *
 * @param {Object} data - the credential data to encrypt
 * @param {string} password - user's password
 * @returns {string} JSON string of { iv, salt, data }
 */
function encryptData(data, password) {
  const iv = crypto.randomBytes(16);
  const pbkdfSalt = crypto.randomBytes(16);
  const key = deriveKeyFromPassword(password, pbkdfSalt);

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(JSON.stringify(data), "utf8", "base64");
  encrypted += cipher.final("base64");

  return JSON.stringify({
    iv: iv.toString("base64"),
    salt: pbkdfSalt.toString("base64"),
    data: encrypted,
  });
}

/**
 * Decrypt data encrypted with encryptData()
 *
 * @param {string} encryptedStr - JSON string from encryptData()
 * @param {string} password - user's password
 * @returns {Object} decrypted credential data
 */
function decryptData(encryptedStr, password) {
  const parsed = JSON.parse(encryptedStr);
  const { iv, data } = parsed;
  const pbkdfSalt = parsed.salt ? Buffer.from(parsed.salt, "base64") : null;

  const key = pbkdfSalt
    ? deriveKeyFromPassword(password, pbkdfSalt)
    : crypto.createHash("sha256").update(password).digest(); // legacy fallback

  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    key,
    Buffer.from(iv, "base64")
  );

  let decrypted = decipher.update(data, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return JSON.parse(decrypted);
}

/**
 * Save encrypted SNARK credentials to disk.
 *
 * @param {string} nidHash - SHA-256 hash of user's NID (used as filename)
 * @param {Object} data - credential data { poseidonFaceHash, secretKey, commitment } or iris equivalent
 * @param {string} password - user's password (for encryption)
 * @param {string} [suffix=''] - optional suffix for biometric type (e.g., '_iris')
 */
function saveCredentials(nidHash, data, password, suffix = '') {
  const encrypted = encryptData(data, password);
  const filePath = path.join(CREDENTIALS_DIR, `${nidHash}${suffix}.enc`);
  fs.writeFileSync(filePath, encrypted, "utf8");
  console.log(`✅ Credentials saved: ${filePath}`);
}

/**
 * Load and decrypt SNARK credentials from disk.
 *
 * @param {string} nidHash - SHA-256 hash of user's NID
 * @param {string} password - user's password (for decryption)
 * @param {string} [suffix=''] - optional suffix for biometric type (e.g., '_iris')
 * @returns {Object} decrypted credential data
 * @throws {Error} if file not found or wrong password
 */
function loadCredentials(nidHash, password, suffix = '') {
  const filePath = path.join(CREDENTIALS_DIR, `${nidHash}${suffix}.enc`);

  if (!fs.existsSync(filePath)) {
    const biometricType = suffix === '_iris' ? 'iris' : 'face';
    throw new Error(
      `No ${biometricType} credentials found for this NID. Please register first with ${biometricType} biometric.`
    );
  }

  const encrypted = fs.readFileSync(filePath, "utf8");
  return decryptData(encrypted, password);
}

/**
 * Check if credentials exist for a given nidHash.
 *
 * @param {string} nidHash - SHA-256 hash of user's NID
 * @param {string} [suffix=''] - optional suffix for biometric type (e.g., '_iris')
 * @returns {boolean}
 */
function hasCredentials(nidHash, suffix = '') {
  const filePath = path.join(CREDENTIALS_DIR, `${nidHash}${suffix}.enc`);
  return fs.existsSync(filePath);
}

module.exports = {
  saveCredentials,
  loadCredentials,
  hasCredentials,
  CREDENTIALS_DIR,
};
