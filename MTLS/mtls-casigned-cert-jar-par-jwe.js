import dotenv from 'dotenv'
dotenv.config()

import http from "http"
import { parse as parseUrl } from 'url'
import open from "open"
import { Issuer, generators, custom } from 'openid-client'
import * as fs from 'fs'
import pkg from 'node-jose';
const { JWK, JWE } = pkg;
import base64url from 'base64url'
import https from 'https';
import axios from 'axios';
import pkg1 from 'jwks-rsa';
const { JwksClient } = pkg1

import pkg2 from 'jsonwebtoken';
const { verify } = pkg2;




const CLIENT_ID = process.env.MTLS_CLIENT_CASIGNED_JAR_PAR_JWE_CBAT_ID;
const CERT_PATH=process.env.MTLS_CLIENT_CASIGNED_JAR_PAR_JWE_CBAT_CERT_PATH;
const KEY_PATH=process.env.MTLS_CLIENT_CASIGNED_JAR_PAR_JWE_CBAT_PRIVATEKEY;
const CA_PATH=process.env.CA_PATH;

const server = http.createServer().listen(8988);

const nonce = generators.nonce();
const redirectUri = "http://127.0.0.1:8988";

server.removeAllListeners('request');
server.once('listening', () => {
  (async () => {

    const cert = fs.readFileSync(CERT_PATH);
    const key = fs.readFileSync(KEY_PATH);
    const ca = fs.readFileSync(CA_PATH);
    const passphrase = "Auth0Dem0";
    
    await custom.setHttpOptionsDefaults({
        cert : cert,
        key:key,
        passphrase: passphrase,
        ca : ca
      });
  
      Issuer[custom.http_options] = () => ({ key, cert, passphrase, ca });

    try {
      // Discover the issuer configuration
      const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);

            // Load the private key for signing the request object (JAR)
            //const privateKey = fs.readFileSync(process.env.MTLS_CLIENT_CASIGNED_JAR_PAR_JWE_CBAT_FORJAR_SAR_PVT_KEY, 'utf8');
            const keystore = JWK.createKeyStore();
            await keystore.add(process.env.MTLS_CLIENT_CASIGNED_JAR_PAR_JWE_CBAT_FORJAR_SAR_PVT_KEY, 'pem');

      // Create a client using MTLS for authentication
      const client = new auth0Issuer.Client({
        client_id: CLIENT_ID,
        token_endpoint_auth_method: 'tls_client_auth', // Use MTLS for client authentication
        tls_client_certificate_bound_access_tokens: true,
        post_logout_redirect_uris: ["https://jwt.io"],
        request_object_signing_alg: 'RS256',
        response_types: ["id_token", "code"],
        redirect_uris: [redirectUri, process.env.MTLS_REDIRECT_URI],
      }, keystore.toJSON(true));

      client[custom.http_options] = () => ({ key, cert, passphrase, ca });

      // Log the client metadata for debugging purposes
      console.log(client.metadata);

      // Create a JWT secured authorization request (JAR)
      const requestObject = await client.requestObject({
        response_type: "code",
        scope: "openid profile",
        redirect_uri: redirectUri,
        nonce: nonce,
        audience: process.env.JWE_API_AUD,
        authorization_details: JSON.stringify([{
          type: "payment_initiation",
          locations: ["https://example.com/payments"],
          transaction_amount: 1234,
          creditorName: "Merchant123",
          account: "DE02100100109307118603",
          remittanceInformationUnstructured: "Ref Number Merchant"
        }])
      });

      console.log("Request Object (JAR):", requestObject);

      client[custom.http_options] = () => ({ key, cert, passphrase, ca });

      // Send the request object to the PAR endpoint
      const parResponse = await client.pushedAuthorizationRequest({
        request: requestObject
      });

      console.log("PAR Response:", parResponse);

      // Construct the URL to start the authorization request
      const authorizationUrl = `https://${process.env.DOMAIN}/authorize?client_id=${process.env.MTLS_CLIENT_CASIGNED_JAR_PAR_JWE_CBAT_ID}&request_uri=${parResponse.request_uri}`;
      console.log("Authorization URL:", authorizationUrl);

      // Open the authorization URL in the default browser
      await open(authorizationUrl, { wait: false });

      // Listen for the authorization code callback
      server.on('request', async (req, res) => {
        res.setHeader('connection', 'close');
        const query = parseUrl(req.url).query;
        console.log(query);

        if (query && query.startsWith("code=")) {
          const code = query.split("=")[1];
          console.log("Authorization Code:", code);

          // Exchange the authorization code for tokens
          const tokenSet = await client.callback(redirectUri, { code }, { nonce });

          console.log("Token Set:", tokenSet);
          console.log('id token claims', tokenSet.claims());

          const httpsAgent = new https.Agent({
            cert,
            key,
            ca,
          });
        
        let config = {
          method: 'get',
          maxBodyLength: Infinity,
          url: process.env.RESOURCE_SERVER_API_FOR_JWE_TOKEN_BINDING_TESTING,
          headers: { 
            'Authorization': `Bearer ${tokenSet.access_token}`
          }, httpsAgent 
        };
        
        axios.request(config)
        .then((response) => {
          console.log("Recieved API Response");
        
          console.log(JSON.stringify(response.data));
          console.log('✅');
        })
        .catch((error) => {
          console.log('❌');
          console.log(error);
        });

          res.end('you can close this now');
          server.close();
        } else {
            console.log('❌');
          res.end('No code param found in the query string! Close this now and try again.');
          server.close();
        }
      });

    } catch (error) {
        console.log('❌');
      console.error('Error:', error);
      process.exitCode = 1;
      server.close();
    }
  })();
});

