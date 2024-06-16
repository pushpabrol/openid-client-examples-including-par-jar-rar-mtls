import dotenv from 'dotenv'
dotenv.config()
import  open from "open";
import { Issuer, generators, custom } from 'openid-client';
import * as fs from 'fs';
import https from 'https';
import axios from 'axios';

import readline from "readline";
const CLIENT_ID = process.env.MTLS_CLIENT_ID_CASIGNED_CBAT;
const CERT_PATH=process.env.MTLS_CLIENT_ID_CASIGNED_CERT_PATH_CBAT;
const KEY_PATH=process.env.MTLS_CLIENT_ID_CASIGNED_PRIVATEKEY_PATH_CBAT;
const CA_PATH=process.env.CA_PATH;
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;




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
    
      // Specify app arguments
     // Issuer[custom.http_options] = () => ({ key, cert, passphrase });
    
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
    response_types: ['code']
    });
    

    const response = await client.pushedAuthorizationRequest({
      response_type: "code",
      audience: process.env.AUD,
      scope: "openid profile " + process.env.AUD_SCOPES,
      "authorization_details": JSON.stringify([ {
        "type": "account_information",
        "actions": [
           "list_accounts",
           "read_balances",
           "read_transactions"
        ],
        "locations": [
           "https://example.com/accounts"
        ]
     },
     {
        "type": "payment_initiation",
        "actions": [
           "initiate",
           "status",
           "cancel"
        ],
        "locations": [
           "https://example.com/payments"
        ],
        "instructedAmount": {
           "currency": "EUR",
           "amount": "123.50"
        },
        "creditorName": "Merchant A",
        "creditorAccount": {
           "iban": "DE02100100109307118603"
        },
        "remittanceInformationUnstructured": "Ref Number Merchant"
     }])
  });
  
  console.log(response);
  
  const url = `${issuer.authorization_endpoint}?client_id=${CLIENT_ID}&request_uri=${response.request_uri}`;
    server.on('request', async (req, res) => {
      res.setHeader('connection', 'close');
      var query = parseUrl(req.url).query;
      console.log(query);
      
        if (query.split("=")[0] == "code") {
          const tokenSet = await client.callback(redirectUri, { "code": query.split("=")[1] }, { custom : { "http_options": { key, cert }}});
          console.log('got', tokenSet);
          console.log('id token claims', tokenSet.claims());
          const userinfo = await client.userinfo(tokenSet);
          console.log('userinfo', userinfo);
          res.end('you can close this now');
          const httpsAgent = new https.Agent({
            cert,
            key,
            ca,
          });
        
        let config = {
          method: 'get',
          maxBodyLength: Infinity,
          url: process.env.RESOURCE_SERVER_API_FOR_TOKEN_BINDING_TESTING,
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