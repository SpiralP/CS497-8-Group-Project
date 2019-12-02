import net, { Socket } from "net";
import fs from "fs";
import crypto, { BinaryLike, KeyLike } from "crypto";
import assert from "assert";
import { cipherAlgorithm, hashAlgorithm, namedCurve } from "./consts";
import { decrypt } from "./utils";

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

// const othersEcdh = crypto.createECDH(namedCurve);
// const othersPublicKey = othersEcdh.generateKeys();

// (async () => {
//   // https://nodejs.org/api/crypto.html#crypto_crypto_generatekeypairsync_type_options

//   const ecdh = crypto.createECDH(namedCurve);
//   ecdh.generateKeys();

//   const privateKey = ecdh.getPrivateKey();
//   const publicKey = ecdh.getPublicKey();

//   const ag = await ECDH(privateKey, othersPublicKey);

//   console.log(ag.length);

//   // await ECDSA(privateKey, publicKey, "hello");
// })();

/*

Handshake
Client -> new connection -> Server
Client -> Init -> Server
Server -> ( Init | close ) -> Client

Init
public key (Chunk)

Chunk
number of data bytes (u16)
data (dynamic bytes)

*/

// load our private and public keys
const trustedKeysString = fs.readFileSync("trustedKeys.json").toString();
const trustedKeys = JSON.parse(trustedKeysString);
const myPrivateKey = fs.readFileSync("serverKey");
const ecdh = crypto.createECDH(namedCurve);
ecdh.setPrivateKey(myPrivateKey);
const myPublicKey = ecdh.getPublicKey();

class ClientConnection {
  socket: Socket;
  sharedSecret?: Buffer;

  constructor(socket: Socket) {
    this.socket = socket;

    (async () => {
      await this.doHandshake();
      await this.startReadLoop();
    })();
  }

  async waitForReadable() {
    await new Promise((resolve) => {
      let fn: any;

      fn = () => {
        this.socket.off("readable", fn);
        resolve();
      };

      this.socket.on("readable", fn);
    });
  }

  async readExactBytes(n: number): Promise<Buffer> {
    while (true) {
      await this.waitForReadable(); // (10 (2 byte number)) (10 data bytes)

      const chunk = this.socket.read(n);
      if (chunk != null) {
        return chunk;
      }
    }
  }

  // https://nodejs.org/api/stream.html#stream_readable_read_size
  async readChunk() {
    const numBytesBuffer = await this.readExactBytes(2);

    // network endian is big endian
    const length = numBytesBuffer.readUInt16BE(0);

    const data = await this.readExactBytes(length);
    return data;
  }

  writeChunk(data: Buffer) {
    const dataLengthBuffer = Buffer.alloc(2);

    // network endian is big endian
    dataLengthBuffer.writeUInt16BE(data.length, 0);
    this.socket.write(dataLengthBuffer);

    this.socket.write(data);
  }

  async doHandshake() {
    console.log("read public key");
    const theirPublicKey = await this.readChunk();

    if (this.isTrusted(theirPublicKey)) {
      console.log("trusted ", this.socket.address());
      this.writeChunk(myPublicKey);

      const ecdh = crypto.createECDH(namedCurve);
      ecdh.setPrivateKey(myPrivateKey);

      this.sharedSecret = ecdh.computeSecret(theirPublicKey);
    } else {
      console.log("not trusted ", this.socket.address());
      this.socket.end();
    }
  }

  isTrusted(theirPublicKey: Buffer) {
    const trusted = trustedKeys.find((element: string) => {
      return Buffer.from(element, 'base64').equals(theirPublicKey);
    });
    if (!trusted) {
      return false;
    } else {
      return true;
    }
  }

  async startReadLoop() {
    while (true) {
      if (this.socket.destroyed) {
        // is this correct??
        break;
      }

      const encryptedData = await this.readChunk();

      const data = decrypt(this.sharedSecret!, encryptedData);

      this.handleMessage(data);
    }
  }

  async handleMessage(message: Buffer) {
    console.log("message: ", message.toString());
  }
}

const connections = [];

const server = net
  .createServer((socket) => {
    //
  })
  .on("error", (err) => {
    console.warn("net error ", err);
  })
  .on("connection", (socket) => {
    console.log("connection from ", socket.address());
    connections.push(new ClientConnection(socket));
  });

// Grab an arbitrary unused port.
server.listen(12345, () => {
  console.log("opened server on ", server.address());
});
