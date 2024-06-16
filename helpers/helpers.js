import {  generateKeyPairSync, randomUUID } from 'crypto';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from "url";
import path from "path";
import readline from "readline";


const __filename = fileURLToPath(import.meta.url);
// First find out the __dirname, then resolve to one higher level in the dir tree
export const __dirname = path.resolve(path.dirname(__filename), "../");
console.log(__dirname);
export const random = randomUUID;

export const generateKeyPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  })
  var pvK =  privateKey.export({
    format: 'pem',
    type: 'pkcs1',
  }).toString();

  //console.log(pvK);
  
  var pubK =  publicKey.export({
    format: 'pem',
    type: 'pkcs1',
  }).toString();

  //console.log(pubK);
  return { "privateKey" : pvK, "publicKey" : pubK};
}

export const setEnvValueOld = (key, value) => {

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

export const setEnvValue = (key, value) => {
  // Read file from the filesystem and split it by line breaks into an array
  const envFilePath = `${__dirname}/.env`;
  let envVars = fs.readFileSync(envFilePath, "utf8").split(os.EOL);

  // Find the index of the line containing the key
  const targetIndex = envVars.findIndex((line) => line.startsWith(`${key}=`));

  // Check if the value contains newlines and should be stringified
  const needsStringify = /\r|\n/.exec(value);

  if (targetIndex !== -1) {
    // If the key exists, replace the line with the new key=value
    if (needsStringify) {
      envVars[targetIndex] = `${key}="${value.replace(/"/g, '\\"')}"`;
    } else {
      envVars[targetIndex] = `${key}=${value}`;
    }
  } else {
    // If the key does not exist, append the new key=value pair
    if (needsStringify) {
      envVars.push(`${key}="${value.replace(/"/g, '\\"')}"`);
    } else {
      envVars.push(`${key}=${value}`);
    }
  }

  // Write the updated content back to the .env file
  fs.writeFileSync(envFilePath, envVars.join(os.EOL));
};


export const askQuestion = (query) => {
  const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
  });

  return new Promise(resolve => rl.question(query, ans => {
      rl.close();
      resolve(ans);
  }))
}

