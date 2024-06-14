import dotenv from 'dotenv'
//dotenv.config( { path :"../.env"})
dotenv.config()
import  open from "open";
import { Issuer, generators, custom } from 'openid-client';
import * as fs from 'fs';
import https from 'https';
import axios from 'axios';


const CLIENT_ID = process.env.MTLS_CLIENT_ID_CASIGNED_CBAT;
const CERT_PATH=process.env.MTLS_CLIENT_ID_CASIGNED_CERT_PATH_CBAT;
const KEY_PATH=process.env.MTLS_CLIENT_ID_CASIGNED_PRIVATEKEY_PATH_CBAT;
const CA_PATH=process.env.CA_PATH;

process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

(async () => {
console.log(process.env);

const cert = fs.readFileSync(CERT_PATH);
const key = fs.readFileSync(KEY_PATH);
const ca = fs.readFileSync(CA_PATH);
const passphrase = "Auth0Dem0";


await custom.setHttpOptionsDefaults({
    cert : cert,
    key:key,
    passphrase: passphrase,
    ca : ca

  });

  // Specify app arguments
  Issuer[custom.http_options] = () => ({ key, cert, passphrase });

  //const issuer = await Issuer.discover(`${process.env.AUTH0_MTLS_ISSUER_URL}`);
  const issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);;
    issuer.log = console;
  const mtlsEndpoints = issuer.mtls_endpoint_aliases;
  if (mtlsEndpoints) {
    console.log('mTLS endpoints discovered: %O', mtlsEndpoints);
}

  
  var client = new issuer.Client({
    client_id: CLIENT_ID,
    token_endpoint_auth_method: 'tls_client_auth',
    tls_client_certificate_bound_access_tokens: true,
    response_type: ["token"]
  
  });

  client[custom.http_options] = () => ({ key, cert, passphrase });
  
  const tokenSet = await client.grant({
      grant_type: "client_credentials",
      audience: process.env.AUD,
      scope: process.env.AUD_SCOPES
  });

  console.log("Recieved token,", tokenSet);

  
  const httpsAgent = new https.Agent({
    cert,
    key,
    ca,
  });

let config = {
  method: 'get',
  maxBodyLength: Infinity,
  url: 'https://resource.desmaximus.com/mtls/protected',
  headers: { 
    'Authorization': `Bearer ${tokenSet.access_token}`
  }, httpsAgent 
};

axios.request(config)
.then((response) => {
  console.log("Recieved API Response");

  console.log(JSON.stringify(response.data));
})
.catch((error) => {
  console.log(error);
});



})();



