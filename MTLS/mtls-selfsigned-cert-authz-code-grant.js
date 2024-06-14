import dotenv from 'dotenv'
dotenv.config()
import  open from "open";
import { Issuer, generators, custom } from 'openid-client';
import * as fs from 'fs';

const CLIENT_ID = process.env.MTLS_CLIENT_ID_SELFSIGNED;
const CERT_PATH=process.env.MTLS_CLIENT_ID_SELFSIGNED_CERT_PATH;
const KEY_PATH=process.env.MTLS_CLIENT_ID_SELFSIGNED_PRIVATEKEY_PATH;
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;
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
    const passphrase = "Auth0Dem0";


    await custom.setHttpOptionsDefaults({
        cert : cert,
        key:key,
        passphrase: passphrase,
      });

    
      // Specify app arguments
      Issuer[custom.http_options] = () => ({ key, cert, passphrase });
    
     const issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);;
     issuer.log = console;
   const mtlsEndpoints = issuer.mtls_endpoint_aliases;
   if (mtlsEndpoints) {
     console.log('mTLS endpoints discovered: %O', mtlsEndpoints);
 }    
    //console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);
    
    //Issuer.Client[custom.http_options] = () => ({ key : key, cert: cert, passphrase: passphrase });
    
    const client = new issuer.Client({
    client_id: `${CLIENT_ID}`,
    redirect_uris: [redirectUri],
    token_endpoint_auth_method: 'self_signed_tls_client_auth',
    tls_client_certificate_bound_access_tokens: true,
    response_types: ['code']
    });
    
    const url = await client.authorizationUrl({
        response_type: "code",
        audience: process.env.NON_HRI_AUD,
        scope: "openid profile " + process.env.AUD_SCOPES
    });
    
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

