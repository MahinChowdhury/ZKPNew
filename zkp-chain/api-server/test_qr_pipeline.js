const snark = require("./crypto/snark");
const QRCode = require("qrcode");
const Jimp = require("jimp");
const jsQR = require("jsqr");
const crypto = require("crypto");

function deriveKeyFromPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");
}

function encryptPayload(payload, password) {
  const iv = crypto.randomBytes(16);
  const pbkdfSalt = crypto.randomBytes(16);
  const key = deriveKeyFromPassword(password, pbkdfSalt);

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(JSON.stringify(payload), "utf8", "base64");
  encrypted += cipher.final("base64");

  return { iv: iv.toString("base64"), salt: pbkdfSalt.toString("base64"), data: encrypted };
}

function decryptPayload(encryptedPayload, password) {
  const parsed = JSON.parse(encryptedPayload);
  const { iv, data } = parsed;
  const pbkdfSalt = parsed.salt ? Buffer.from(parsed.salt, "base64") : null;
  const key = deriveKeyFromPassword(password, pbkdfSalt);
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, Buffer.from(iv, "base64"));
  let decrypted = decipher.update(data, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return JSON.parse(decrypted);
}

async function testFullQRPipeline() {
  await snark.initPoseidon();

  // 1. Generate fake 64D float embedding (mimicking FaceNet)
  const floatEmb = new Array(64).fill(0).map(() => (Math.random() - 0.5) * 0.5);
  const salt = crypto.randomBytes(16).toString("hex");
  const password = "mysecretpassword";

  // 2. Compute registration data
  const regData = await snark.computeRegistrationData(floatEmb, salt);
  console.log("Registered faceHash: ", regData.faceHash.toString());

  // 3. Create QR code payload
  const qrPayload = {
    nidHash: "dummyNidHash",
    salt,
    biometricMode: "face",
    faceEmbedding: floatEmb,
  };

  const encrypted = encryptPayload(qrPayload, password);
  const encryptedStr = JSON.stringify(encrypted);

  // 4. Generate QR code buffer (PNG)
  const qrBuffer = await QRCode.toBuffer(encryptedStr, { errorCorrectionLevel: "L" });
  console.log("QR Buffer size:", qrBuffer.length, "bytes");

  // 5. Decode QR code buffer (simulating vote upload)
  const img = await Jimp.read(qrBuffer);
  const { data, width, height } = img.bitmap;
  const code = jsQR(new Uint8ClampedArray(data), width, height);
  if (!code) throw new Error("QR decode failed!");

  // 6. Decrypt QR payload
  const qrData = decryptPayload(code.data, password);
  console.log("Decrypted faceEmbedding length:", qrData.faceEmbedding.length);

  // 7. Compute faceHash from decrypted QR embedding
  const voteScaled = snark.scaleEmbedding(qrData.faceEmbedding);
  const voteFaceHash = await snark.poseidonHashEmbedding(voteScaled, BigInt("0x" + salt));
  console.log("Decrypted QR faceHash:  ", voteFaceHash.toString());

  console.log("Do hashes match?", regData.faceHash === voteFaceHash);
}

testFullQRPipeline().catch(console.error);
