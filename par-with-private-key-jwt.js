import dotenv from 'dotenv'
dotenv.config()

import open from "open";
import { Issuer, generators } from 'openid-client';
import readline from "readline";

import pkg from 'node-jose';
const { JWK } = pkg;

var privateKey = process.env.PVT_KEY;


(async () => {
    try {
        
        var keystore = JWK.createKeyStore();
        await keystore.add(privateKey, "pem");

        const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);

        const client = new auth0Issuer.Client({
            client_id: process.env.PKJWT_CLIENT_ID,
            token_endpoint_auth_method: 'private_key_jwt',
            redirect_uris: [process.env.PKJWT_REDIRECT_URI],
            post_logout_redirect_uris : ["https://jwt.io"]

        },keystore.toJSON(true));

        auth0Issuer.log = console;

        const responseType = "code";
        const response = await client.pushedAuthorizationRequest({
            audience: process.env.AUD,
            scope: `openid ${process.env.AUD_SCOPES}`,
            nonce: "132123",
            response_type: responseType,
            "ext-authz-transfer-amount": "100000",
            "ext-authz-transfer-recipient": "abc"

        });

        console.log(response);

        const url = `https://${process.env.DOMAIN}/authorize?client_id=${process.env.PKJWT_CLIENT_ID}&request_uri=${response.request_uri}`;

        console.log(`Authorize URL: ${url}`);

        (async () => {
            // Specify app arguments
            await open(url, { app: ['google chrome'] });
            if(responseType === "code") { 
            const code = await askQuestion("Please enter the code from the response? ");
            console.log(code);
            const params = { "code": code };
            console.log(params);

            const tokenSet = await client.callback(process.env.PKJWT_REDIRECT_URI, params, { "nonce": "132123" });

            console.log(tokenSet);

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


    } catch (err) {
        console.error(err);
    }
})();







