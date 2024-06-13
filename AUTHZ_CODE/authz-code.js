import dotenv from 'dotenv'
dotenv.config()

import http from "http"
import { parse  as parseUrl} from 'url'

const server = http.createServer().listen(8988);
import open from "open";
import { Issuer, generators } from 'openid-client';
const nonce = generators.nonce();
server.removeAllListeners('request');

server.once('listening', () => {
  (async () => {
    const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
    const { address, port } = server.address();
    const hostname = "127.0.0.1"

    console.log(hostname);

    const client = new auth0Issuer.Client({
      client_id: process.env.RWA_CLIENT_ID,
      client_secret: process.env.RWA_CLIENT_SECRET,
      redirect_uris: ["http://127.0.0.1:8988"],
      response_types: ['token','id_token','code'],
    
    });

    server.on('request', async (req, res) => {
      res.setHeader('connection', 'close');
      var query = parseUrl(req.url).query;
      console.log(query);
      
        if (query.split("=")[0] == "code") {
          const tokenSet = await client.callback(
            "http://127.0.0.1:8988", { "code": query.split("=")[1] }, {"nonce" : nonce },
          );

          console.log('got', tokenSet);
          console.log('id token claims', tokenSet.claims());

          const userinfo = await client.userinfo(tokenSet);
          console.log('userinfo', userinfo);

          res.end('you can close this now');
          server.close();
        }
        else {
          res.end('No code param found in the query string!. Close this now and try again!');
          server.close();
        }

      

    });
    var url = client.authorizationUrl({
      audience: process.env.NON_HRI_AUD,
      scope: `openid ${process.env.AUD_SCOPES}`,
      nonce: nonce,
      response_type: "code"
  });
  console.log(url);
    await open(url, { wait: false });
  })().catch((err) => {
    console.error(err);
    process.exitCode = 1;
    server.close();
  });
});