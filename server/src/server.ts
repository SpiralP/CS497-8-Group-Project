import * as net from "net";
import crypto, { BinaryLike, KeyObject, KeyLike } from "crypto";
import assert from "assert";
import util from "util";

const namedCurve = "secp256k1";
const hashAlgorithm = "sha256";

// TODO research iv for gcm??
const cipherAlgorithm = "aes-128-ctr";
// https://nodejs.org/api/crypto.html

// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

// https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256/

// Protocol:
// Transport Layer Security (TLS)

// Key Exchange:
// Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)

// Authentication:
// Elliptic Curve Digital Signature Algorithm (ECDSA)

// Encryption:
// Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)

// Hash:
// Secure Hash Algorithm 256 (SHA256)

// const server = net.createServer((socket) => {
//   socket.write('Echo server\r\n');
//   socket.pipe(socket);
// });

// server.listen(1337, '127.0.0.1');

function sign(privateKey: KeyLike, data: BinaryLike) {
  const sign = crypto.createSign(hashAlgorithm);
  sign.update(data);
  sign.end();
  const signature = sign.sign(privateKey);

  return signature;
}

function verify(publicKey: KeyLike, data: BinaryLike, signature: Buffer) {
  const verify = crypto.createVerify(hashAlgorithm);
  verify.update(data);
  verify.end();
  const isVerified = verify.verify(publicKey, signature);

  return isVerified;
}

async function ECDSA(privateKey: KeyLike, publicKey: KeyLike, message: string) {
  // Authentication:
  // Elliptic Curve Digital Signature Algorithm (ECDSA)

  const messageHash = crypto
    .createHash(hashAlgorithm)
    .update(message)
    .digest();
  console.log(`messageHash: ${messageHash.toString("hex")}`);

  const signature = sign(privateKey, messageHash);

  console.log(`signature: `, signature);

  assert(verify(publicKey, messageHash, signature));

  // const certBody = message;
  // net.send(certBody + signature);
}

function hash(data: Buffer) {
  const h = crypto.createHash("sha256");
  h.update(data);
  return h.digest();
}

async function ECDH(
  myPrivateKey: Buffer,
  otherPublicKey: Buffer,
  secret: crypto.CipherKey
) {
  const ivLen = 16;
  const iv = crypto.randomBytes(ivLen);
  const cipher = crypto.createCipheriv(cipherAlgorithm, secret, iv);
  cipher.update("messsaaage");
  return cipher.final();
}

const othersEcdh = crypto.createECDH(namedCurve);
const othersPublicKey = othersEcdh.generateKeys();

(async () => {
  // https://nodejs.org/api/crypto.html#crypto_crypto_generatekeypairsync_type_options

  const ecdh = crypto.createECDH(namedCurve);
  ecdh.generateKeys();

  const privateKey = ecdh.getPrivateKey();
  const publicKey = ecdh.getPublicKey();

  const secret = ecdh.computeSecret(othersPublicKey);

  const secretHash = hash(secret).slice(0, 16); // take 16 bytes

  console.log(await ECDH(privateKey, othersPublicKey, secretHash));

  // await ECDSA(privateKey, publicKey, "hello");
})();

// console.log(privateKey.export({
//   format: "pem",
//   type: "sec1"
// }).toString(), publicKey.export({
//   format: "pem",
//   type: "spki" // Simple public-key infrastructure
// }).toString());

// // console.log(crypto.privateEncrypt(privateKey, Buffer.from(message)));
