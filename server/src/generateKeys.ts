import crypto from "crypto";
import fs from "fs";
import { namedCurve } from "./consts";

function genClient() {
  const ecdh = crypto.createECDH(namedCurve);
  ecdh.generateKeys();
  const privateKey = ecdh.getPrivateKey();
  const publicKey = ecdh.getPublicKey();

  fs.writeFileSync("client", privateKey);
  fs.writeFileSync("client.pub", publicKey);

  const obj = [publicKey.toString("base64")];
  fs.writeFileSync("trustedKeys.json", JSON.stringify(obj));
}

function genServer() {
  const ecdh = crypto.createECDH(namedCurve);
  ecdh.generateKeys();
  const privateKey = ecdh.getPrivateKey();

  fs.writeFileSync("serverKey", privateKey);
}

genClient();
genServer();
