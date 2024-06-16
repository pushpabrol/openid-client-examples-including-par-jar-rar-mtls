import dotenv from 'dotenv'
dotenv.config()

import http from "http"

const server = http.createServer().listen(8988);
import { parse as parseUrl } from 'url'

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

    var privateKeyAuth = process.env.FORJAR_TEAUTH_PVT_KEY;
    var privateKeySAR = process.env.FORJAR_SAR_PVT_KEY;

    var keystoreSAR = JWK.createKeyStore();
    await keystoreSAR.add(privateKeySAR, "pem");
    // console.log(sar);

    var client = new auth0Issuer.Client({
      client_id: process.env.PKJARJWT_CLIENT_ID,
      token_endpoint_auth_method: 'private_key_jwt',
      post_logout_redirect_uris: ["https://jwt.io"],
      request_object_signing_alg: 'RS256',
      response_types: ["id_token", "code"],
      redirect_uris: [redirectUri, process.env.PKJARJWT_REDIRECT_URI]

    }, keystoreSAR.toJSON(true));

    console.log(client.metadata);

    auth0Issuer.log = console;


    var req = await client.requestObject({
      response_type: "code", scope: "openid profile",
      redirect_uri: redirectUri,
      nonce: nonce,
      audience:process.env.AUD,
      "authorization_details": JSON.stringify([ {
        "type": "payment_initiation",
        "locations": [
          "https://example.com/payments"
        ],
        "transaction_amount": 1234,
        "creditorName": "Merchant123",
        "account":  "DE02100100109307118603",
        "remittanceInformationUnstructured": "Ref Number Merchant"
      }])
    });

    console.log(req);

    var privateKeyAuthStore = JWK.createKeyStore();
    await privateKeyAuthStore.add(privateKeyAuth, "pem");

    var client = new auth0Issuer.Client({
      client_id: process.env.PKJARJWT_CLIENT_ID,
      token_endpoint_auth_method: 'private_key_jwt',
      post_logout_redirect_uris: ["https://jwt.io"],
      request_object_signing_alg: 'RS256',
      response_types: ["id_token", "code"],
      redirect_uris: [redirectUri, process.env.PKJARJWT_REDIRECT_URI]

    }, privateKeyAuthStore.toJSON(true));

    const response = await client.pushedAuthorizationRequest({
      request: req,

    });

    console.log(response);

    const url = `https://${process.env.DOMAIN}/authorize?client_id=${process.env.PKJARJWT_CLIENT_ID}&request_uri=${response.request_uri}`;


    console.log(url);

    console.log(client.metadata);


    server.on('request', async (req, res) => {
      res.setHeader('connection', 'close');
      var query = parseUrl(req.url).query;
      console.log(query);

      if (query.split("=")[0] == "code") {

        const code = query.split("=")[1];
        const params = { "code": code };
        console.log(params);

        //var keystoreAuth1 = JWK.createKeyStore();
        await privateKeyAuthStore.add(privateKeyAuth, "pem");
        //console.log(auth);
        client = new auth0Issuer.Client({
          client_id: process.env.PKJARJWT_CLIENT_ID,
          token_endpoint_auth_method: 'private_key_jwt',
          post_logout_redirect_uris: ["https://jwt.io"],
          request_object_signing_alg: 'RS256',
          response_types: ["id_token", "code"],
          redirect_uris: [redirectUri, process.env.PKJARJWT_REDIRECT_URI]

        }, privateKeyAuthStore.toJSON(true));

        console.log
        const tokenSet = await client.callback(redirectUri, { "code": query.split("=")[1] }, { "nonce": nonce });

        console.log(tokenSet);

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
