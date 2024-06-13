import dotenv from 'dotenv'
dotenv.config()

import  open from "open";
import { Issuer, generators } from 'openid-client';

import { askQuestion } from '../helpers/helpers.js';
const nonce = generators.nonce();

const code_verifier = generators.codeVerifier();
// store the code_verifier in your framework's session mechanism, if it is a cookie based solution
// it should be httpOnly (not readable by javascript) and encrypted.
const code_challenge = generators.codeChallenge(code_verifier);
const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);

const client = new auth0Issuer.Client({
  client_id: process.env.NON_CONFIDENTIAL_CLIENT_ID,
  token_endpoint_auth_method: "none",
  redirect_uris: [process.env.REDIRECT_URI],
  response_types: ['code']

});

const response = await client.pushedAuthorizationRequest({
    audience: process.env.AUD,
    scope: `openid ${process.env.AUD_SCOPES}`,
    nonce: nonce,
    response_type: "code",  
    code_challenge,
    code_challenge_method: 'S256',
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
 }])

});

console.log(response);
const url = `https://${process.env.DOMAIN}/authorize?client_id=${process.env.NON_CONFIDENTIAL_CLIENT_ID}&request_uri=${response.request_uri}`;

(async () => {
  // Specify app arguments
  await open(url, {app: ['google chrome']});

  const code = await askQuestion("Please enter the code from the response? ");
  console.log(code);

  const params = {"code" : code};
  console.log(params);

  const tokenSet = await client.callback(process.env.REDIRECT_URI, params,{"nonce" : nonce,"code_verifier": code_verifier });

  console.log(tokenSet);


})();

