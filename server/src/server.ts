import net, { Socket } from "net";
import fs from "fs";
import crypto from "crypto";
import { PromiseSocket } from "promise-socket";
import { namedCurve } from "./consts";
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
  socket: PromiseSocket<Socket>;
  sharedSecret?: Buffer;

  constructor(socket: Socket) {
    this.socket = new PromiseSocket(socket);

    (async () => {
      await this.doHandshake();
      await this.startReadLoop();
    })();
  }

  async readBytes(n: number): Promise<Buffer> {
    while (true) {
      const buffer = await this.socket.read(n);
      if (!buffer) {
        throw new Error("closed");
      }

      if (!Buffer.isBuffer(buffer)) {
        throw new Error("not a buffer " + typeof buffer);
      }

      return buffer;
    }
  }

  async readChunk() {
    const numBytesBuffer = await this.readBytes(2);

    // network endian is big endian
    const length = numBytesBuffer.readUInt16BE(0);

    const data = await this.readBytes(length);

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
      console.log("trusted ", this.socket.stream.address());
      this.writeChunk(myPublicKey);

      const ecdh = crypto.createECDH(namedCurve);
      ecdh.setPrivateKey(myPrivateKey);

      this.sharedSecret = ecdh.computeSecret(theirPublicKey);
    } else {
      console.log("not trusted ", this.socket.stream.address());
      this.socket.end();
    }
  }

  isTrusted(theirPublicKey: Buffer) {
    const trusted = trustedKeys.find((element: string) => {
      return Buffer.from(element, "base64").equals(theirPublicKey);
    });
    if (!trusted) {
      return false;
    } else {
      return true;
    }
  }

  async startReadLoop() {
    while (true) {
      // just throws an error when closed
      const encryptedData = await this.readChunk();

      const data = decrypt(this.sharedSecret!, encryptedData);

      this.handleMessage(data);
    }
  }

  async handleMessage(message: Buffer) {
    console.log(`message len ${message.length}`);
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
