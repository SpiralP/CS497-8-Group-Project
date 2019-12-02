import crypto, { BinaryLike, KeyLike } from "crypto";
import { cipherAlgorithm, hashAlgorithm, namedCurve } from "./consts";

export function hash(data: Buffer) {
  const h = crypto.createHash("sha256");
  h.update(data);
  return h.digest();
}

export function encrypt(secret: Buffer, message: Buffer) {
  // const ecdh = crypto.createECDH(namedCurve);
  // ecdh.setPrivateKey(myPrivateKey);

  // const secret = ecdh.computeSecret(othersPublicKey);

  const secretHash = hash(secret).slice(0, 16); // take 16 bytes

  const ivLen = 16;
  const iv = crypto.randomBytes(ivLen);
  const cipher = crypto.createCipheriv(cipherAlgorithm, secretHash, iv);

  const concatBuffer = Buffer.concat([iv, cipher.update(message), cipher.final()]);
  return concatBuffer;
}

export function decrypt(secret: Buffer, messageWithIv: Buffer) {
  // const ecdh = crypto.createECDH(namedCurve);
  // ecdh.setPrivateKey(myPrivateKey);

  // const secret = ecdh.computeSecret(othersPublicKey);

  const secretHash = hash(secret).slice(0, 16); // take 16 bytes

  const iv = messageWithIv.slice(0, 16);
  const message = messageWithIv.slice(16);
  const decipher = crypto.createDecipheriv(cipherAlgorithm, secretHash, iv);

  return Buffer.concat([decipher.update(message), decipher.final()]);
}
