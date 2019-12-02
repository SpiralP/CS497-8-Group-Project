import crypto from "crypto";
import fs from "fs";
import { namedCurve } from "./consts";

const ecdh = crypto.createECDH(namedCurve);
ecdh.generateKeys();
const privateKey = ecdh.getPrivateKey();
const publicKey = ecdh.getPublicKey();

fs.writeFileSync("client", privateKey);
fs.writeFileSync("client.pub", publicKey);
fs.writeFileSync("clientb64", publicKey.toString('base64'));
