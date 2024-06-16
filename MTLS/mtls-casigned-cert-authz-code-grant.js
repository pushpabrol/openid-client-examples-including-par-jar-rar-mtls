import dotenv from 'dotenv'
dotenv.config()
import  open from "open";
import { Issuer, generators, custom } from 'openid-client';
import * as fs from 'fs';
import https from 'https';
import axios from 'axios';

import readline from "readline";
const CLIENT_ID = process.env.MTLS_CLIENT_ID_CASIGNED;
const CERT_PATH=process.env.MTLS_CLIENT_ID_CASIGNED_CERT_PATH;
const KEY_PATH=process.env.MTLS_CLIENT_ID_CASIGNED_PRIVATEKEY_PATH;
const CA_PATH=process.env.CA_PATH;


const redirectUri = "http://127.0.0.1:8988";
import http from "http"

const server = http.createServer().listen(8988);
import { parse  as parseUrl} from 'url'

server.removeAllListeners('request');
server.once('listening', () => {

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

    Issuer[custom.http_options] = () => ({ key, cert, passphrase, ca });
    
    //const issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);;
  //const issuer = new Issuer({"issuer":"https://secureaccess.desmaximus.com/","authorization_endpoint":"https://mtls.secureaccess.desmaximus.com/authorize","token_endpoint":"https://mtls.secureaccess.desmaximus.com/oauth/token","device_authorization_endpoint":"https://mtls.secureaccess.desmaximus.com/oauth/device/code","userinfo_endpoint":"https://mtls.secureaccess.desmaximus.com/userinfo","mfa_challenge_endpoint":"https://mtls.secureaccess.desmaximus.com/mfa/challenge","jwks_uri":"https://mtls.secureaccess.desmaximus.com/.well-known/jwks.json","registration_endpoint":"https://mtls.secureaccess.desmaximus.com/oidc/register","revocation_endpoint":"https://mtls.secureaccess.desmaximus.com/oauth/revoke","scopes_supported":["openid","profile","offline_access","name","given_name","family_name","nickname","email","email_verified","picture","created_at","identities","phone","address"],"response_types_supported":["code","token","id_token","code token","code id_token","token id_token","code token id_token"],"code_challenge_methods_supported":["S256","plain"],"response_modes_supported":["query","fragment","form_post"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["HS256","RS256","PS256"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","private_key_jwt","tls_client_auth","self_signed_tls_client_auth"],"claims_supported":["aud","auth_time","created_at","email","email_verified","exp","family_name","given_name","iat","identities","iss","name","nickname","phone_number","picture","sub"],"request_uri_parameter_supported":false,"request_parameter_supported":true,"token_endpoint_auth_signing_alg_values_supported":["RS256","RS384","PS256"],"tls_client_certificate_bound_access_tokens":true,"pushed_authorization_request_endpoint":"https://mtls.secureaccess.desmaximus.com/oauth/par","require_pushed_authorization_requests":false,"end_session_endpoint":"https://mtls.secureaccess.desmaximus.com/oidc/logout","require_signed_request_object":false,"request_object_signing_alg_values_supported":["RS256","RS384","PS256"]});

  const issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);;
  issuer.log = console;
const mtlsEndpoints = issuer.mtls_endpoint_aliases;
if (mtlsEndpoints) {
  console.log('mTLS endpoints discovered: %O', mtlsEndpoints);
}

    
    const client = new issuer.Client({
    client_id: `${CLIENT_ID}`,
    redirect_uris: [redirectUri],
    token_endpoint_auth_method: 'tls_client_auth',
    tls_client_certificate_bound_access_tokens: true,
    response_types: ['code'],
    });

    client[custom.http_options] = () => ({ key, cert, passphrase, ca });

    const url = await client.authorizationUrl({
        response_type: "code",
        scope: "openid"
    });
    
    server.on('request', async (req, res) => {
      res.setHeader('connection', 'close');
      var query = parseUrl(req.url).query;
      console.log(query);
      
        if (query.split("=")[0] == "code") {
          const tokenSet = await client.callback(redirectUri, { "code": query.split("=")[1] }, { custom : { "http_options": { key, cert, passphrase, ca }}});

          console.log('got', tokenSet);
          console.log('id token claims', tokenSet.claims());
          client[custom.http_options] = () => ({ key, cert, passphrase, ca });
          const userinfo = await client.userinfo(tokenSet);
          console.log('userinfo', userinfo);
  
          res.end('you can close this now');


          server.close();
        }
        else {
          res.end('No code param found in the query string!. Close this now and try again!');
          server.close();
        }
  
  
    });
  
    await open(url, { wait: false });
    })().catch((err) => {
      console.error(err);
      process.exitCode = 1;
      server.close();
    });
   
});

