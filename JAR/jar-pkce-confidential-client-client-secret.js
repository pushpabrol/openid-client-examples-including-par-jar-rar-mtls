import dotenv from 'dotenv'
dotenv.config()

import  open from "open";
import { Issuer, generators } from 'openid-client';

import readline from "readline";

import pkg from 'node-jose';
const { JWK } = pkg;

const code_verifier = generators.codeVerifier();
// store the code_verifier in your framework's session mechanism, if it is a cookie based solution
// it should be httpOnly (not readable by javascript) and encrypted.

const code_challenge = generators.codeChallenge(code_verifier);

const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
//console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);

var privateKey = process.env.JAR_PVT_KEY;



(async () => {
  try {

      var keystore = JWK.createKeyStore();
      await keystore.add(privateKey, "pem");
      const client = new auth0Issuer.Client({
          client_id: process.env.PKJAR_CLIENT_ID,
          client_secret : process.env.PKJAR_CLIENT_SECRET,
          token_endpoint_auth_method: 'client_secret_post',
          post_logout_redirect_uris: ["https://jwt.io"],
          request_object_signing_alg : 'RS256',
          response_types : ["id_token", "code"],
          redirect_uri : process.env.PKJAR_REDIRECT_URI
          

      }, keystore.toJSON(true));

      auth0Issuer.log = console;


      var req = await client.requestObject({
        audience: process.env.AUD,
        scope: `openid ${process.env.AUD_SCOPES}`,
        response_type: "code",  
        code_challenge,
        code_challenge_method: 'S256',
        redirect_uri: process.env.PKJAR_REDIRECT_URI
    
    });
      console.log(req);

      const url = await client.authorizationUrl({
          request: req
      });


  // Specify app arguments
  await open(url, {app: ['google chrome']});

  const code = await askQuestion("Please enter the code from the response? ");
  console.log(code);

  const params = {"code" : code};
  console.log(params);

  const tokenSet = await client.callback(process.env.PKJAR_REDIRECT_URI, params,{"code_verifier": code_verifier });

  console.log(tokenSet);
    }
    catch(e){
      console.log(e);
    }

})();


function askQuestion(query) {
  const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
  });

  return new Promise(resolve => rl.question(query, ans => {
      rl.close();
      resolve(ans);
  }))
}