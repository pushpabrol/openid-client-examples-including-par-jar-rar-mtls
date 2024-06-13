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

    const code_verifier = generators.codeVerifier();
    // store the code_verifier in your framework's session mechanism, if it is a cookie based solution
    // it should be httpOnly (not readable by javascript) and encrypted.

    const code_challenge = generators.codeChallenge(code_verifier);

    const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
    //console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);

    var privateKey = process.env.JAR_PVT_KEY;


      var keystore = JWK.createKeyStore();
      await keystore.add(privateKey, "pem");
      const client = new auth0Issuer.Client({
          client_id: process.env.PKJAR_CLIENT_ID,
          client_secret : process.env.PKJAR_CLIENT_SECRET,
          token_endpoint_auth_method: 'client_secret_post',
          post_logout_redirect_uris: ["https://jwt.io"],
          request_object_signing_alg : 'RS256',
          response_types : ["id_token", "code"],
          redirect_uris : [process.env.PKJAR_REDIRECT_URI, redirectUri]
          

      }, keystore.toJSON(true));

      auth0Issuer.log = console;


      var req = await client.requestObject({
        audience: process.env.AUD,
        scope: `openid ${process.env.AUD_SCOPES}`,
        response_type: "code",  
        code_challenge,
        code_challenge_method: 'S256',
        redirect_uri: redirectUri,
        "authorization_details": JSON.stringify([{
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
        "type": "customer_information",
        "locations": [
           "https://example.com/customers"
        ],
        "actions": [
           "read"
        ],
        "datatypes": [
           "contacts"
        ]
     }]),
        nonce:nonce
    
    });
      console.log(req);

      const url = await client.authorizationUrl({
          request: req
      });

      server.on('request', async (req, res) => {
        res.setHeader('connection', 'close');
        var query = parseUrl(req.url).query;
        console.log(query);
        
          if (query.split("=")[0] == "code") {
            const tokenSet = await client.callback(redirectUri, { "code": query.split("=")[1] }, { "nonce": nonce,"code_verifier": code_verifier});

    
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
