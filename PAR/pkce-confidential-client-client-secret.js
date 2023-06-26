import dotenv from 'dotenv'
dotenv.config()

import  open from "open";
import { Issuer, generators } from 'openid-client';

import { askQuestion } from '../helpers/helpers.js';

const code_verifier = generators.codeVerifier();
// store the code_verifier in your framework's session mechanism, if it is a cookie based solution
// it should be httpOnly (not readable by javascript) and encrypted.

const code_challenge = generators.codeChallenge(code_verifier);

const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
//console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);

const client = new auth0Issuer.Client({
  client_id: process.env.RWA_CLIENT_ID,
  client_secret: process.env.RWA_CLIENT_SECRET,
  redirect_uris: [process.env.RWA_REDIRECT_URI],
  response_types: ['code'],

});

const url =  client.authorizationUrl({
    audience: process.env.AUD,
    scope: `openid ${process.env.AUD_SCOPES}`,
    response_type: "code",  
    code_challenge,
    code_challenge_method: 'S256'

});


(async () => {
  // Specify app arguments
  await open(url, {app: ['google chrome']});

  const code = await askQuestion("Please enter the code from the response? ");
  console.log(code);

  const params = {"code" : code};
  console.log(params);

  const tokenSet = await client.callback(process.env.RWA_REDIRECT_URI, params,{"code_verifier": code_verifier });

  console.log(tokenSet);


})();


