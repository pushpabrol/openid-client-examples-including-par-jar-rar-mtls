import dotenv from 'dotenv'
dotenv.config()

import http from "http"
import { parse  as parseUrl} from 'url'
import base64url from 'base64url'

import pkg1 from 'jwks-rsa';
const { JwksClient } = pkg1

import pkg2 from 'jsonwebtoken';
const { verify } = pkg2;
const server = http.createServer().listen(8988);
import open from "open";
import { Issuer, generators } from 'openid-client';
const nonce = generators.nonce();
server.removeAllListeners('request');

import pkg from 'node-jose';
const { JWK, JWE } = pkg;

server.once('listening', () => {
  (async () => {
    const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
    const { address, port } = server.address();
    const hostname = "127.0.0.1"

    console.log(hostname);

    const client = new auth0Issuer.Client({
      client_id: process.env.RWA_CLIENT_ID,
      client_secret: process.env.RWA_CLIENT_SECRET,
      redirect_uris: ["http://127.0.0.1:8988"],
      response_types: ['token','id_token','code']
    
    });

    server.on('request', async (req, res) => {
      res.setHeader('connection', 'close');
      var query = parseUrl(req.url).query;
      console.log(query);
      
        if (query.split("=")[0] == "code") {
          const tokenSet = await client.callback(
            "http://127.0.0.1:8988", { "code": query.split("=")[1] }, {"nonce" : nonce },
          );

          console.log('got', tokenSet);
          console.log('id token claims', tokenSet.claims());
          console.log('Access Token is encrypted and should be decrypted by the resource server that has the private key. For demo purposes we will decrypt the token here!');
          const key = await JWK.asKey(process.env.JWE_PRIVATE_KEY.replace(/\n/g,"\r\n"),"pem");
          const decrypted = await JWE.createDecrypt(key).decrypt(tokenSet.access_token);
          const accessToken = decrypted.plaintext.toString('utf-8');
          console.log("Access Token: ", accessToken);
          
          console.log('Access Token Signature Verification & decoded payload!');
          const jwksCl = new JwksClient({
            jwksUri: auth0Issuer.metadata.jwks_uri,
            requestHeaders: {}, // Optional
            timeout: 30000 // Defaults to 30s
          });

          
          
          const header = JSON.parse(base64url.decode(accessToken.split(".")[0]));
          console.log(header);
          const signingKey = await jwksCl.getSigningKey(header.kid);
          const decoded = verify(accessToken,signingKey.getPublicKey());
          console.log(decoded);
          console.log('✅');
          res.end('you can close this now');
          server.close();
        }
        else {
          console.log('❌');
          res.end('No code param found in the query string!. Close this now and try again!');
          server.close();
        }

      

    });
    var url = client.authorizationUrl({
      audience: process.env.JWE_API_AUD,
      scope: `openid ${process.env.AUD_SCOPES}`,
      nonce: nonce,
      response_type: "code"

  });
  console.log(url);
    await open(url, { wait: false });
  })().catch((err) => {
    console.log('❌');
    console.error(err);
    process.exitCode = 1;
    server.close();
  });
});


