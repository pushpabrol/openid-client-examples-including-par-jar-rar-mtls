import dotenv from 'dotenv'
dotenv.config()
import  open from "open";
import { Issuer, generators } from 'openid-client';

const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
//console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);

const nonce = generators.nonce();

const client = new auth0Issuer.Client({
  client_id: process.env.RWA_CLIENT_ID,
  client_secret: process.env.RWA_CLIENT_SECRET,
  redirect_uris: [process.env.RWA_REDIRECT_URI],
  response_types: ['token','id_token','code']

});

const url = await client.authorizationUrl({
    audience: process.env.NON_HRI_AUD,
    scope: `openid ${process.env.AUD_SCOPES}`,
    nonce: nonce,
    response_type: "token id_token"

});

(async () => {
  // Specify app arguments
  await open(url, {app: ['google chrome']});

})();




