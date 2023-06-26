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
        //console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);
        console.log(auth0Issuer);
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
            redirect_uris : [process.env.PKJWT_REDIRECT_URI, redirectUri]
    
        }, keystore.toJSON(true));

        auth0Issuer.log = console;


        var req = await client.requestObject({ response_type: "code", scope: "openid profile", 
        redirect_uri : redirectUri, nonce : nonce });
        console.log(req);

        const url = await client.authorizationUrl({
            request: req
        });

        console.log(url);

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
        
          await open(url, { wait: false });
          })().catch((err) => {
            console.error(err);
            process.exitCode = 1;
            server.close();
          });
        });        

