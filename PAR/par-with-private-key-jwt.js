import dotenv from 'dotenv'
dotenv.config()

import http from "http"

const server = http.createServer().listen(8988);
import { parse  as parseUrl} from 'url'

import open from "open";
import { Issuer, generators } from 'openid-client';
import pkg from 'node-jose';
const { JWK } = pkg;

const nonce = generators.nonce();

const redirectUri = "http://127.0.0.1:8988";

server.removeAllListeners('request');

server.once('listening', () => {
  (async () => {
    const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
    const { address, port } = server.address();
    const hostname = "127.0.0.1"

        var privateKey = process.env.PVT_KEY;
        var keystore = JWK.createKeyStore();
        await keystore.add(privateKey, "pem");

        const client = new auth0Issuer.Client({
            client_id: process.env.PKJWT_CLIENT_ID,
            token_endpoint_auth_method: 'private_key_jwt',
            redirect_uris: [redirectUri],
            post_logout_redirect_uris : ["https://jwt.io"]

        },keystore.toJSON(true));

        auth0Issuer.log = console;

        const responseType = "code";
        const response = await client.pushedAuthorizationRequest({
            audience: process.env.AUD,
            scope: `openid ${process.env.AUD_SCOPES}`,
            nonce: nonce,
            response_type: responseType,
            "authorization_details": JSON.stringify([ {
                "type": "payment_initiation",
                "locations": [
                  "https://example.com/payments"
                ],
                
                  "roles": []
              
              }])

        });

        console.log(response);

        const url = `https://${process.env.DOMAIN}/authorize?client_id=${process.env.PKJWT_CLIENT_ID}&request_uri=${response.request_uri}`;

        console.log(`Authorize URL: ${url}`);


        server.on('request', async (req, res) => {
            res.setHeader('connection', 'close');
            var query = parseUrl(req.url).query;
            console.log(query);
            
              if (query.split("=")[0] == "code") {
                const tokenSet = await client.callback(redirectUri, { "code": query.split("=")[1] }, { "nonce": nonce});

        
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







