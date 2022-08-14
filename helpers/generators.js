import {  generateKeyPairSync, randomUUID } from 'crypto';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from "url";
import path from "path";

const __filename = fileURLToPath(import.meta.url);
// First find out the __dirname, then resolve to one higher level in the dir tree
export const __dirname = path.resolve(path.dirname(__filename), "../");

export const random = randomUUID;

export const generateKeyPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  })
  var pvK =  privateKey.export({
    format: 'pem',
    type: 'pkcs1',
  }).toString();

  console.log(pvK);
  
  var pubK =  publicKey.export({
    format: 'pem',
    type: 'pkcs1',
  }).toString();

  console.log(pubK);
  return { "privateKey" : pvK, "publicKey" : pubK};
}

export const setEnvValue = (key, value) => {

  // read file from hdd & split if from a linebreak to a array
  const ENV_VARS = fs.readFileSync(`${__dirname}/.env`, "utf8").split(os.EOL);

  // find the env we want based on the key
  const target = ENV_VARS.indexOf(ENV_VARS.find((line) => {
      return line.match(new RegExp(key));
  }));
  
  // replace the key/value with the new value
  if(/\r|\n/.exec(value)) ENV_VARS.splice(target, 1, `${key}="${value}"`);
  else ENV_VARS.splice(target, 1, `${key}=${value}`);

  // write everything back to the file system
  fs.writeFileSync(`${__dirname}/.env`, ENV_VARS.join(os.EOL));

}

