import dotenv from 'dotenv'
dotenv.config()

import  open from "open";
import { Issuer, generators } from 'openid-client';

import readline from "readline";

const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
//console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);

const client = new auth0Issuer.Client({
  client_id: process.env.RWA_CLIENT_ID,
  client_secret: process.env.RWA_CLIENT_SECRET,
  redirect_uris: [process.env.RWA_REDIRECT_URI],
  response_types: ['token','id_token','code'],

});

const response = await client.pushedAuthorizationRequest({
    audience: process.env.AUD,
    scope: `openid ${process.env.AUD_SCOPES}`,
    nonce: "132123",
    response_type: "token id_token", 
    "ext-type": "payment_initiation",
      "ext-actions": "initiate:status:cancel"  ,
      "ext-locations": "https://example.com/payments",
      "ext-instructedAmount":"amount:123.50EUR",
      "ext-debtorAccount":"iban:DE40100100103307118608",
      "ext-creditorName":"Merchant123",
      "ext-creditorAccount":"iban:DE02100100109307118603",
      "ext-remitInfoUnstructured":"Ref Number Merchant"
    

});


console.log(response);


const url = `https://${process.env.DOMAIN}/authorize?client_id=${process.env.RWA_CLIENT_ID}&request_uri=${response.request_uri}`;

(async () => {
  // Specify app arguments
  await open(url, {app: ['google chrome']});

})();

