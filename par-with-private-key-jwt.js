import dotenv from 'dotenv'
dotenv.config()

import open from "open";
import { Issuer, generators } from 'openid-client';
import readline from "readline";

import pkg from 'node-jose';
const { JWK } = pkg;

const algorithm = 'RS256'
var privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAh9FAeUZ/W3Fr9USgg5MFYqDoy7sYNyH0Eej1xwyf66HMTVW/
v3ff8gmsSher9d1hefgAO229K9Bx+ddoO5M0O9v+ejQc8rUUwkqy21XtHjwoewg7
kUMbVeFWHAVLUkCrifdgh3EPvbX2vbwxg7kJystLCZYaogF/efnIE2mnWeZhBsuV
eVSMZYb/cJCU/u6M2dFcB86TIJz7wOanliiDx8hU2CG0bqT1G6In0eLN+gT+En60
vrMyyaTUYaE3lwjrdkXnq5OjcO724YnhazgoJBWWeU5p7G3Caayowp0uL7PhEEHX
WAAJdPqTP2vFnQyySpv7OpFCmvubnP/Xu8PjjQIDAQABAoIBAGmN8WPPrG9vKQ5H
tdBMVSUgFY0w7VL76mp4+Xsnjqpc5yE7gXjXO48qgWJcH2NIGNfoLJYDZcBFki8w
gGu8rh3Pjml/Uvg2T9nooDTjBRQ4gOWNsm3lD7uhE4FXhAB7DlZ9keHxtuAkKY2w
U3MiPkAD21+p7yz1qRMtU5fyxwOQYq1H+xjG8WOzsB5c6T79CE+gB6WSB008e4mm
NR/U8li9LeGZDOCrVewsA5pyDW9aFkp77YFnUQQD1u5nufhivfkUXHycJ3jC3yiP
TOYJVq/Jxe/LeRWt7yWFhmDa0OdK6tx56mNMJf3uyqpZqJnU7uUnxYUnoZ3V1GVm
SKBS8QECgYEA82HLdQ5cwZz/lhhRE7aqlEmdRaodo+qXW/GqXLZYYEfzMEp81VaC
BtstjOq1+rY0/YUVE5vZMPyeaGDiVEhxDMKWNH3dLgJd8p6leWDRmRRE3wGj0TEt
Cd9jVBVZbYmrZknLQtO3sORVG3jyhfsHBZcAu8x5lgcaWxKmilIFpu0CgYEAjtvX
lYhR+tb6h8199iE9ytesTjprZheimx/gMKr8/aTtfHTClVzVECujPQ2bQnSeU2uJ
F8vD2Y4dLOTROKZbCsgkE6KEL+f3KF8qtE9ob1n1TFAaku+CW5R3SkAxKDnkZsEX
Zr4rsM2UOa1NHVExz2575suAg9QgXm33zkT7+yECgYByxFLkx/kFc7syVBUnbqPR
eUUobKe9fAoT2Um0nmfePw92XimvkDOQeBpqsONPbkxeoDroHD220+j+33Dava5R
jhC2gAOkhok2t4jgS7+Kp/wyDNvq8X2DgkucgtTAyoKAoZuvz5Z3W7SmV8pFU7Jj
+GjoJevPy1mqSIkwAK2ZoQKBgEvMf826f+z9Jf7qXHw81QGMf8MeIiAQSFnQhu6r
uwKGAPA5L4l6sR4cWUeqsYeIQv12IE588lS7n+VTH2PUeJf265VzdHnKtYw5Onpj
a8ExVQMBuafe5ybaVpUSDEMQvIx8xYLhQmNUIOKdfj4g97HdKGaj8XOBGQ+hf4t1
dNGhAoGBAJ7/SUO+w0nHB56V5tMoQ61pOmVl6jRVOVpQyU5S7wK5jzcT3UnF6bkF
+VQu/UlsJrzzbDrYHOGQeAGDh6a5uufv+VlT4EHO9jKY9oGz0UPA4Nl1E992CFVc
lZIqFO+ejohHR2f9Pg2aAeWZ1Lr9uDCdTaQsXTNmC++zCB7rqhEy
-----END RSA PRIVATE KEY-----`;


(async () => {
    try {
        
        var keystore = JWK.createKeyStore();
        await keystore.add(privateKey, "pem");

        const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);

        console.log(auth0Issuer);
        //console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);


        const client = new auth0Issuer.Client({
            client_id: process.env.PKJWT_CLIENT_ID,
            token_endpoint_auth_method: 'private_key_jwt',
            redirect_uris: [process.env.PKJWT_REDIRECT_URI]

        },keystore.toJSON(true));

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







