import dotenv from 'dotenv'
dotenv.config()

import open from "open";
import { Issuer, generators } from 'openid-client';
import readline from "readline";

import pkg from 'node-jose';
const { JWK } = pkg;

const algorithm = 'RS256'
var privateKey = process.env.PVT_KEY.replace(/\n/g,"\r\n");


(async () => {
    try {

        var keystore = JWK.createKeyStore();
        await keystore.add(privateKey, "pem");
        const code_verifier = generators.codeVerifier();
        // store the code_verifier in your framework's session mechanism, if it is a cookie based solution
        // it should be httpOnly (not readable by javascript) and encrypted.

        const code_challenge = generators.codeChallenge(code_verifier);


        const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);

        //console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);


        const client = new auth0Issuer.Client({
            client_id: process.env.PKJWT_CLIENT_ID,
            token_endpoint_auth_method: 'private_key_jwt',
            redirect_uris: [process.env.PKJWT_REDIRECT_URI]

        },keystore.toJSON(true));

        const responseType = "code";
        const url = client.authorizationUrl({
            audience: process.env.AUD,
            scope: `openid ${process.env.AUD_SCOPES}`,
            response_type: responseType,
            code_challenge,
            code_challenge_method: 'S256',
            "ext-authz-transfer-amount": "100000",
            "ext-authz-transfer-recipient": "abc"

        });


        (async () => {
            // Specify app arguments
            await open(url, { app: ['google chrome'] });
            if(responseType === "code") { 
            const code = await askQuestion("Please enter the code from the response? ");
            console.log(code);
            const params = { "code": code };
            console.log(params);

            const tokenSet = await client.callback(process.env.PKJWT_REDIRECT_URI, params, {"code_verifier": code_verifier });

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







