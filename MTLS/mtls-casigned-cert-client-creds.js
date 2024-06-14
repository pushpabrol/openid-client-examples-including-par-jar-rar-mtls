import dotenv from 'dotenv'
//dotenv.config( { path :"../.env"})
dotenv.config()
import  open from "open";
import { Issuer, generators, custom } from 'openid-client';
import * as fs from 'fs';


const CLIENT_ID = process.env.MTLS_CLIENT_ID_CASIGNED;
const CERT_PATH=process.env.MTLS_CLIENT_ID_CASIGNED_CERT_PATH;
const KEY_PATH=process.env.MTLS_CLIENT_ID_CASIGNED_PRIVATEKEY_PATH;
const CA_PATH=process.env.CA_PATH;
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

(async () => {

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

  //const issuer = await Issuer.discover(process.env.AUTH0_MTLS_ISSUER_URL);
  const issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);;
  console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);

  issuer.log = console;
const mtlsEndpoints = issuer.mtls_endpoint_aliases;
if (mtlsEndpoints) {
  console.log('mTLS endpoints discovered: %O', mtlsEndpoints);
}

  
  var client = new issuer.Client({
    client_id: CLIENT_ID,
    token_endpoint_auth_method: 'tls_client_auth',
    response_type: ["token"],
    tls_client_certificate_bound_access_tokens: true
  
  });

  client[custom.http_options] = () => ({ key, cert, passphrase });
  
  const token = await client.grant({
      grant_type: "client_credentials",
      audience: process.env.AUD,
      scope: process.env.AUD_SCOPES
  });

  console.log(token);


})();



