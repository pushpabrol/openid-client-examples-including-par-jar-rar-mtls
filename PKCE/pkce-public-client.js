import dotenv from 'dotenv'
dotenv.config()

import http from "http"

const server = http.createServer().listen(8988);
import { parse  as parseUrl} from 'url'

import open from "open";
import { Issuer, generators } from 'openid-client';
import anyBody from 'body';

const nonce = generators.nonce();
const code_verifier = generators.codeVerifier();
const code_challenge = generators.codeChallenge(code_verifier);

const redirectUri = "http://127.0.0.1:8988";

server.removeAllListeners('request');

server.once('listening', () => {
  (async () => {
    const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
    const { address, port } = server.address();
    const hostname = "127.0.0.1"


const client = new auth0Issuer.Client({
  client_id: process.env.NON_CONFIDENTIAL_CLIENT_ID,
  token_endpoint_auth_method: "none",
  redirect_uris: [redirectUri],
  response_types: ['code','token id_token']

});

const url =  client.authorizationUrl({
    audience: process.env.NON_HRI_AUD,
    scope: `openid ${process.env.AUD_SCOPES}`,
    response_type: "code",  
    code_challenge,
    code_challenge_method: 'S256',
    nonce : nonce

});

  server.on('request', async (req, res) => {
    res.setHeader('connection', 'close');
    var query = parseUrl(req.url).query;
    console.log(query);
    
      if (query.split("=")[0] == "code") {

        const tokenSet = await client.callback(redirectUri, { "code": query.split("=")[1] },{"nonce" : nonce,"code_verifier": code_verifier });

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
