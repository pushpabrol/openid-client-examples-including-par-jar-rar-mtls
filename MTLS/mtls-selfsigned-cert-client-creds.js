import dotenv from 'dotenv'
//dotenv.config( { path :"../.env"})
dotenv.config()
import  open from "open";
import { Issuer, generators, custom } from 'openid-client';
import * as fs from 'fs';


const CLIENT_ID = process.env.MTLS_CLIENT_ID_SELFSIGNED;
const CERT_PATH=process.env.MTLS_CLIENT_ID_SELFSIGNED_CERT_PATH;
const KEY_PATH=process.env.MTLS_CLIENT_ID_SELFSIGNED_PRIVATEKEY_PATH;
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

(async () => {

const cert = fs.readFileSync(CERT_PATH);
const key = fs.readFileSync(KEY_PATH);
const passphrase = "Auth0Dem0";


await custom.setHttpOptionsDefaults({
    cert : cert,
    key:key,
    passphrase: passphrase

  });

  // Specify app arguments
  Issuer[custom.http_options] = () => ({ key, cert, passphrase });

  const issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);;
  issuer.log = console;
const mtlsEndpoints = issuer.mtls_endpoint_aliases;
if (mtlsEndpoints) {
  console.log('mTLS endpoints discovered: %O', mtlsEndpoints);
} 
  
  var client = new issuer.Client({
    client_id: CLIENT_ID,
    token_endpoint_auth_method: 'self_signed_tls_client_auth',
    tls_client_certificate_bound_access_tokens: true,
    response_type: ["token"]
  
  });

  client[custom.http_options] = () => ({ key, cert, passphrase });
  
  const token = await client.grant({
      grant_type: "client_credentials",
      audience: process.env.AUD,
      scope: process.env.AUD_SCOPES
  });

  console.log(token);


})();



