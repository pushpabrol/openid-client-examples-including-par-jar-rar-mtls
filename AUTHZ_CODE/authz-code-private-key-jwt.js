import dotenv from 'dotenv'
dotenv.config()
import http from "http"

const server = http.createServer().listen(8988);
import { parse  as parseUrl} from 'url'

import open from "open";
import { Issuer, generators } from 'openid-client';
import anyBody from 'body';

const nonce = generators.nonce();

const redirectUri = "http://127.0.0.1:8988";

import pkg from 'node-jose';
const { JWK } = pkg;

var privateKey = process.env.PVT_KEY.replace(/\n/g,"\r\n");
server.removeAllListeners('request');

server.once('listening', () => {
    (async () => {
      const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
      const { address, port } = server.address();
      const hostname = "127.0.0.1"


        var keystore = JWK.createKeyStore();
        await keystore.add(privateKey, "pem");
        const code_verifier = generators.codeVerifier();
        // store the code_verifier in your framework's session mechanism, if it is a cookie based solution
        // it should be httpOnly (not readable by javascript) and encrypted.

        const code_challenge = generators.codeChallenge(code_verifier);

        const client = new auth0Issuer.Client({
            client_id: process.env.PKJWT_CLIENT_ID,
            token_endpoint_auth_method: 'private_key_jwt',
            redirect_uris: [redirectUri]

        },keystore.toJSON(true));

        const responseType = "code";
        const url = client.authorizationUrl({
            audience: process.env.AUD,
            scope: `openid ${process.env.AUD_SCOPES}`,
            response_type: responseType,
            nonce:nonce

        });

        server.on('request', async (req, res) => {
            res.setHeader('connection', 'close');
            var query = parseUrl(req.url).query;
            console.log(query);
            
              if (query.split("=")[0] == "code") {
        
                const tokenSet = await client.callback(redirectUri, { "code": query.split("=")[1] },{"nonce" : nonce });
        
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
        
          await open(url, { wait: true });
          })().catch((err) => {
            console.error(err);
            process.exitCode = 1;
            server.close();
          });
        });
        








