import net, { Socket } from "net";
import fs from "fs";
import crypto, { BinaryLike, KeyLike } from "crypto";
import assert from "assert";
import { cipherAlgorithm, hashAlgorithm, namedCurve } from "./consts";

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

async function ECDH(myPrivateKey: Buffer, otherPublicKey: Buffer) {
  const ecdh = crypto.createECDH(namedCurve);
  ecdh.setPrivateKey(myPrivateKey);

  const secret = ecdh.computeSecret(othersPublicKey);

  const secretHash = hash(secret).slice(0, 16); // take 16 bytes

  const ivLen = 16;
  const iv = crypto.randomBytes(ivLen);
  const cipher = crypto.createCipheriv(cipherAlgorithm, secretHash, iv);
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

  const ag = await ECDH(privateKey, othersPublicKey);

  console.log(ag.length);

  // await ECDSA(privateKey, publicKey, "hello");
})();

/*

Handshake
Client -> new connection -> Server
Client -> Init -> Server
Server -> ( Init | close ) -> Client

Init
public key (Chunk)

Chunk
number of data bytes (8 bytes)
data (dynamic bytes)

*/

const myPrivateKey = fs.readFileSync("privateKey");

class ClientConnection {
  socket: Socket;

  constructor(socket: Socket) {
    this.socket = socket;
  }

  readChunk(): Buffer {
    const numBytes = parseInt(this.socket.read(8));
    const data = this.socket.read(numBytes);
    return data;
  }

  writeChunk(data: Buffer) {
    const buf = new Buffer(2);
    buf.writeUInt16BE(data.length, 0);
    this.socket.write(buf);
  }

  doHandshake() {
    const theirPublicKey = this.readChunk();

    if (this.isTrusted(theirPublicKey)) {
      console.warn(`trusted ${this.socket.address()}`);
      this.writeChunk(myPrivateKey);

      this.startReadLoop();
    } else {
      console.warn(`not trusted ${this.socket.address()}`);
      this.socket.end();
    }
  }

  isTrusted(theirPublicKey: Buffer) {
    // TODO
    return true;
  }

  startReadLoop() {
    while (true) {
      if (this.socket.destroyed) {
        // is this correct??
        break;
      }

      const data = this.readChunk();
      this.handleMessage(data);
    }
  }

  handleMessage(message: Buffer) {
    console.log(`message: ${message}`);
  }
}

const server = net
  .createServer((socket) => {
    socket.end();
  })
  .on("error", (err) => {
    console.warn(`net error ${err}`);
  })
  .on("connection", (socket) => {
    console.log(`connection from ${socket.address()}`);
    new ClientConnection(socket);
  });

// Grab an arbitrary unused port.
server.listen(() => {
  console.log(`opened server on ${server.address()}`);
});
