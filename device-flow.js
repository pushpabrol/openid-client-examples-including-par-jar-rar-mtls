import dotenv from 'dotenv'
dotenv.config()
import  open from "open";
import { Issuer } from 'openid-client';
import QRCode from 'qrcode';



import readline from "readline";

const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);
//console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);

const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

const client = new auth0Issuer.Client({
  client_id: process.env.NATIVE_CLIENT_ID,
  grant_types: [GRANT_TYPE],
  response_types: [],
  redirect_uris: [],
  token_endpoint_auth_method: 'none',
});

(async () => {
const handle = await client.deviceAuthorization();
console.log(handle);


//await open(handle.verification_uri_complete, { wait: false });
var i = handle.expires_in;

var timer = waitingForVerification(i); 

QRCode.toString(handle.verification_uri_complete,{type:'terminal',margin:4, scale: 1, small: true},
                    function (err, QRcode) {
    if(err) return console.log("error occurred")
    // Printing the generated code
    console.log(QRcode);
  

})


const tokenSet = await handle.poll()
console.log("\n Done!");
clearInterval(timer);

  console.log('got', tokenSet);
  console.log('id token claims', tokenSet.claims());

  const userinfo = await client.userinfo(tokenSet);
  console.log('userinfo', userinfo);

})().catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });

  
  function waitingForVerification(i) {

    var countdownTimer = setInterval(function() {
      process.stdout.clearLine();
      process.stdout.cursorTo(0);
        process.stdout.write("Expires in " + i + " seconds!");
        i = i - 1;

        if (i <= 0) {
            clearInterval(countdownTimer);
        }

    }, 1000);
return countdownTimer;
  }

