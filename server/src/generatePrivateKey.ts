import crypto from "crypto";
import fs from "fs";
import { namedCurve } from "./consts";

const ecdh = crypto.createECDH(namedCurve);
ecdh.generateKeys();
const privateKey = ecdh.getPrivateKey();

fs.writeFileSync("privateKey", privateKey);
