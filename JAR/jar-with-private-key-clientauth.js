import dotenv from 'dotenv'
dotenv.config()
import  open from "open";
import { Issuer, generators } from 'openid-client';

import readline from "readline";

import pkg from 'node-jose';
const { JWK } = pkg;

const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
//console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);

// PKJARJWT_REDIRECT_URI=https://jwt.io
// FORJAR_TEAUTH_PVT_KEY="-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAvlulA9zIWbd4x9H4FklcMv4poYL3j/3+7VDiu58aEnpbe7eT\nf0ZEhXKvYy93mdvdTxpKXN/XgEgU49dJYIHNr3LWvFg4NMnT54Axr8HHq6oHyztS\naO1RzOmzukynTylLQ5JUMprZfSGBd1f/Zq2QC94zKG6w9s7F2P+ecspzgRMsLM/J\nXX2vDYdsx7Eq61Us2ascHENkb0+s9yz5XBiJtFfWXK/HQRZR/EUl7VQ88EOlUam9\n8lHzBqcWNhPWuL/l1Uw9jqYilxVV95O2nIGJkNWUuHqgourgrYnfC3PYHC0W9Bbg\nZN4uuIlMD7Zcre9QBXCyvs9ddoih4a1RyjZvBwIDAQABAoIBAHlai1RvB/rKEGGy\n5emvUuvfREMG7zQIxOAd1K2vvDtTbcbtPUbCUSSR/GXK+QBJPkkThZy3xvas/URT\nFyBDIBFdsK/ZvdtJX6ISA5r8eoJhnx5c7yidQqzTwBRgkbjRpn2pZ6vrNAOlvJeM\nrfGTbGVkflCkYIS3RUIVk7myfvglWUIF1xvNTFRTaMsyEpyge463lTsYq2SoZ7UJ\nqHwBB9H2M/LBkbRq4njLjutXlYFMoPpe98Jr8LtaJkSR2krtLHXNqv/wgomqT/Le\nSN58qvIMVTCOwDPwQZ905GEkGmVTrhxRQ7EDQF2j07sqT8+zpwCIo1aqr0hn0xGN\nz/GlJ8ECgYEA+cwOcpK7g0P2mwy3jTS/Hh05ZAMh4DWTJhfYArdPR9rzjmXIgHib\nuW9rXNNqeAbsqE2bShNO1IdnrCJd1jHsYHRNPBB+ot/ll+ax1qjBO+Yu5G7crpo2\nQaQxzcSgqBaHpKL26PCNyO+ggix/rqR/gZyTsjKC3SjftLGnASbkn28CgYEAwxW8\n2M3R1OqU1Plh/YDw1slEksEIYRIt+nMXHfiTBOaQurYXaPYi2/oy7YEbTB/DD4CD\n42eUfTrfnziYxPbWUZ8W+JYHhgaRKDuvuvZ8n9RrYXXIfS54vEDd47OLn4fgTAJB\n9gTT23LbGqCiO6n55lqma66/HpDSJ4kvKbIqXekCgYEAygrSZLlqEXIXNLHEhOH0\n81aP5OTjsYWjz1vZy9iYt3XRKYwJ8F+dFQ+ZtysJIqv3HuomgHO9fwlGQWRKocUf\ne6SWE88DnpmaCpL9pLI6GUjFBN7mgBMbb1xvLA+uIkaW0AM/0ok/JRcsrB1x6MAE\nocETdT6Funwk9PH8MmJS6OECgYAOFfe4v8Oy1+0/I3KL10+McqPc5MsyFxnyx3SX\n2WbkJ7GziYpPLdZ+g6ZBt9y8tl5jNChRtxzlneafnHqLXjdDVXVXJZ4Nc1Pvz790\nhG+jKrdGJjb/sudM0HI1CrW+IxVy54bTuK2DXturJIYSQMemdk0l4UwzbMl/yUv6\ner7MYQKBgCRqlWUSJ1IkrYWQ+ycLliJ6D7UoW1xzyKTKTVFxfSfybCl4Y+6t2go1\nmsn+5qzUwvuFeK10sSWzyTLIUVJ8tbRMlY00FgcmREQc2zT7FKhXKz1zJewWdSBA\n9zdm9bvD7tP/IWbR7TRHX1Vk3QpV1FhwE21JP2C5HC4y8Xr4OZHW\n-----END RSA PRIVATE KEY-----\n"
// FORJAR_SAR_PVT_KEY="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEApmOHBXK082mJPYNvWBO2ZYi085DQoZ1ZfuWVuE3ULCifieSB\njKtsAuE7MtvbrlBWRcLiJLlNuwDaJwwJh6yJTM+2Ms7GFo37ZCYeraYa1knpPmtQ\n2NqW2cIlobnbzUAjUaVZwBy4Icg8bcXa+b1TOeTi4VXeUBlBhX1rGCY2JHl20wjJ\nrJlwVpTops0/iyVp6znvn6VGEkyPIAZbJFUQSW3/Hhwl2BvoHHl6X7XlFKi8PvPB\naXfB98RblpcMgULEtr6IT+5Ue3IRLY1yTVf49rUNKb8bDS4BgtQrYXy8mtqqG1FF\nZHHXYU+UrLCZQVwhbm+OGVUCqvrmxcv9vXhrgwIDAQABAoIBAHnGBZ97H+u1pXeb\npfW0F52fu682oTpmyoUQyc6lR086O+jTj+y/2MESzhyew9yDd2B/DLsL01O1f/Nr\n392n7KSGsDXnFxqStxXIwFMeai3C0i2YpQbQk+6zJI+EUtWYx0CN3222lxxCS9eb\nInP8l9ibJ2D7U0UT9twXujVmYeG2xZezrSm202XT7hIIcZ/QoUkNbIuDJwSPk6dr\neFXww7RJhNm0NEsgAHmbpGCItujK4bFIUgf9wuOJfVuUx7YXX5OcRmyfZGMiX9zz\ndXw9TkQpJkppt5vvBKHC2iTzKz3JTv+j9fq3c0L51XRcqCJSsCHxsQ6gXVLr5jAo\n2nNAYYECgYEA0fSXxk+NFs5kNDFrO7HCWoUARfoOiHTPDJ7CES5DQ59MNK5Q/52M\nxsoda/bZIvliv31n+FpgN3H8Z8Z4YdCsIu9fB4ikS+CHBIp9oxSwpz5m7Vy6Y6yO\nVTf6nwlMFaOxEfddCAumNFTkB+UN+n7agKboK2RVIwhB//p6pWHJuNECgYEAyuD/\nIZC8LVBi+7DZRjkQDEtwTvieOIZgXeVr1EatxN3P7mob5zr8CQn2nW2NqXCjze+g\n508vDX5vU5SWHsA4lEUkkWeiah2PuOMXkU9Py30gvmhQQsekQpZt4kxKnKuE0NxP\nq5ShSmShOEnrRPLTgtKp2UeTlwfDHzhgFWfxdBMCgYEAuCTWmVBcZoxOxpgxfQHD\nfLD6NGXFKVmJ33++pmL1C/JDXFEnKYp9Vj0e4Pp4J3yjZ2AOOHzLttV6k2o3W1My\nJtHbfzgRIZuj0A/HcalL5uOMUtLph1Jo48VdQu9ck/4l56QVLGFLPMrX1TTItdNc\nwUmih6xQH5G2kVSXDUZfLoECgYALebyUrnYmbgSbTf6MPVAOEfpRTTjN47Pxu7dk\ns3bCyvUm/DOF2c1FyZ18fCTmL6vkSyijzNPRhJRRevce2CqbIGoYG2+RZwipIZdE\nreLKlNJUUtwvWtGMvquKgFw8Dmud0Mhk4SxaY+TGpU+8f6u9G6Nl2emcQmEkE/FD\nZLTApwKBgQCLcyPbPhXRje9j3rV4mfrZdG8cl3s/Y+2mn6icYkFpIqa0rO25l7V7\nt2dLBoqyrxqLroQQIYfiKzUE8y4zNcpbISsNSKLg5VMbbEd235QYEk3tYfbM6yn9\nq91YSEAWjSwAbSRcyxphnalVH/jE/quYjJquf2yMl9oxC/yWDYFrxA==\n-----END RSA PRIVATE KEY-----\n"


var privateKeyAuth = process.env.FORJAR_TEAUTH_PVT_KEY;
var privateKeySAR = process.env.FORJAR_SAR_PVT_KEY;


(async () => {
    try {

        var keystoreSAR = JWK.createKeyStore();
        var sar = await keystoreSAR.add(privateKeySAR, "pem");
        // console.log(sar);

        var client = new auth0Issuer.Client({
            client_id: process.env.PKJARJWT_CLIENT_ID,
            token_endpoint_auth_method: 'private_key_jwt',
            post_logout_redirect_uris: ["https://jwt.io"],
            request_object_signing_alg : 'RS256',
            response_types : ["id_token", "code"],
            redirect_uri : process.env.PKJARJWT_REDIRECT_URI
   
        }, keystoreSAR.toJSON(true));

        console.log(client.metadata);

        auth0Issuer.log = console;

        var req = await client.requestObject({ response_type: "code", scope: "openid profile", 
        redirect_uri : process.env.PKJAR_REDIRECT_URI});
        console.log(req);

        const url = await client.authorizationUrl({
            request: req
        });

         console.log(url);

        console.log(client.metadata);


  // Specify app arguments
  await open(url, {app: ['google chrome']});

  const code = await askQuestion("Please enter the code from the response? ");
  console.log(code);

  const params = {"code" : code};
  console.log(params);
  
  var keystoreAuth = JWK.createKeyStore();
  var auth = await keystoreAuth.add(privateKeyAuth, "pem");
  //console.log(auth);
  client = new auth0Issuer.Client({
    client_id: process.env.PKJARJWT_CLIENT_ID,
    token_endpoint_auth_method: 'private_key_jwt',
    post_logout_redirect_uris: ["https://jwt.io"],
    request_object_signing_alg : 'RS256',
    response_types : ["id_token", "code"],
    redirect_uri : process.env.PKJARJWT_REDIRECT_URI

}, keystoreAuth.toJSON(true));

  console.log
  const tokenSet = await client.callback(process.env.PKJAR_REDIRECT_URI, params,{});

  console.log(tokenSet);
}
catch(e) {
    console.log(e);
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