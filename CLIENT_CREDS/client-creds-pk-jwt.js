import dotenv from 'dotenv'
dotenv.config()
import { Issuer, generators } from 'openid-client';

import pkg from 'node-jose';
const { JWK } = pkg;

const privateKey = process.env.PVT_KEY;

(async () => {
    try {
        
        const keystore = JWK.createKeyStore();
        await keystore.add(privateKey, "pem");

        const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);

        const client = new auth0Issuer.Client({
            client_id: process.env.PKJWT_CLIENT_ID,
            token_endpoint_auth_method: 'private_key_jwt',
            response_types: ["token"]

        },keystore.toJSON(true));

        //auth0Issuer.log = console;
        
        const token = await client.grant({
            grant_type: "client_credentials",
            audience : process.env.NON_HRI_AUD
        });
      
        console.log(token);


    } catch (err) {
        console.error(err);
    }
})();







