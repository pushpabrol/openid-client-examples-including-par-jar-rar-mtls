import dotenv from 'dotenv'
dotenv.config()
import  open from "open";
import { Issuer } from 'openid-client';

const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
//console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);

const client = new auth0Issuer.Client({
  client_id: process.env.RWA_CLIENT_ID,
  client_secret: process.env.RWA_CLIENT_SECRET,
  redirect_uris: [process.env.RWA_REDIRECT_URI],
  response_types: ['token','id_token','code']

});

const response = await client.pushedAuthorizationRequest({
    audience: process.env.AUD,
    scope: `openid ${process.env.AUD_SCOPES}`,
    nonce: "132123",
    response_type: "token id_token", 
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


const url = `https://${process.env.DOMAIN}/authorize?client_id=${process.env.RWA_CLIENT_ID}&request_uri=${response.request_uri}`;

(async () => {
  // Specify app arguments
  await open(url, {app: ['google chrome']});

})();

