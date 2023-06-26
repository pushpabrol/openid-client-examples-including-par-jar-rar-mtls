import dotenv from 'dotenv'
dotenv.config()
import { Issuer, generators } from 'openid-client';


(async () => {
    try {
        

        const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);

        const client = new auth0Issuer.Client({
            client_id: process.env.RWA_CLIENT_ID,
            client_secret: process.env.RWA_CLIENT_SECRET,
            token_endpoint_auth_method: 'client_secret_post',
            response_types: ["token"]

        });

        //auth0Issuer.log = console;
        
        const token = await client.grant({
            grant_type: "client_credentials",
            audience : process.env.AUD
        });
      
        console.log(token);


    } catch (err) {
        console.error(err);
    }
})();







