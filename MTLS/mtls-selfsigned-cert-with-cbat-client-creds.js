import dotenv from 'dotenv'
//dotenv.config( { path :"../.env"})
dotenv.config()
import  open from "open";
import { Issuer, generators, custom } from 'openid-client';
import * as fs from 'fs';


const CLIENT_ID = process.env.MTLS_CLIENT_ID_SELFSIGNED_CBAT;
const CERT_PATH=process.env.MTLS_CLIENT_ID_SELFSIGNED_CERT_PATH_CBAT;
const KEY_PATH=process.env.MTLS_CLIENT_ID_SELFSIGNED_PRIVATEKEY_PATH_CBAT;
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

(async () => {
console.log(process.env);

const cert = fs.readFileSync(CERT_PATH);
const key = fs.readFileSync(KEY_PATH);
const passphrase = "Auth0Dem0";


await custom.setHttpOptionsDefaults({
    cert : cert,
    key:key,
    passphrase: passphrase

  });

  // Specify app arguments
  Issuer[custom.http_options] = () => ({ key, cert, passphrase });

  //const issuer = await Issuer.discover(`${process.env.AUTH0_MTLS_ISSUER_URL}`);
  const issuer = new Issuer({"issuer":"https://mtls.secureaccess.desmaximus.com/","authorization_endpoint":"https://mtls.secureaccess.desmaximus.com/authorize","token_endpoint":"https://mtls.secureaccess.desmaximus.com/oauth/token","device_authorization_endpoint":"https://mtls.secureaccess.desmaximus.com/oauth/device/code","userinfo_endpoint":"https://mtls.secureaccess.desmaximus.com/userinfo","mfa_challenge_endpoint":"https://mtls.secureaccess.desmaximus.com/mfa/challenge","jwks_uri":"https://mtls.secureaccess.desmaximus.com/.well-known/jwks.json","registration_endpoint":"https://mtls.secureaccess.desmaximus.com/oidc/register","revocation_endpoint":"https://mtls.secureaccess.desmaximus.com/oauth/revoke","scopes_supported":["openid","profile","offline_access","name","given_name","family_name","nickname","email","email_verified","picture","created_at","identities","phone","address"],"response_types_supported":["code","token","id_token","code token","code id_token","token id_token","code token id_token"],"code_challenge_methods_supported":["S256","plain"],"response_modes_supported":["query","fragment","form_post"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["HS256","RS256","PS256"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","private_key_jwt","tls_client_auth","self_signed_tls_client_auth"],"claims_supported":["aud","auth_time","created_at","email","email_verified","exp","family_name","given_name","iat","identities","iss","name","nickname","phone_number","picture","sub"],"request_uri_parameter_supported":false,"request_parameter_supported":true,"token_endpoint_auth_signing_alg_values_supported":["RS256","RS384","PS256"],"tls_client_certificate_bound_access_tokens":true,"pushed_authorization_request_endpoint":"https://mtls.secureaccess.desmaximus.com/oauth/par","require_pushed_authorization_requests":false,"end_session_endpoint":"https://mtls.secureaccess.desmaximus.com/oidc/logout","require_signed_request_object":false,"request_object_signing_alg_values_supported":["RS256","RS384","PS256"]});
  console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);
  
  var client = new issuer.Client({
    client_id: CLIENT_ID,
    token_endpoint_auth_method: 'none',
    response_type: ["token"]
  
  });

  client[custom.http_options] = () => ({ key, cert, passphrase });
  
  const token = await client.grant({
      grant_type: "client_credentials",
      audience: process.env.AUD,
      scope: process.env.AUD_SCOPES,
  });

  console.log(token);


})();



