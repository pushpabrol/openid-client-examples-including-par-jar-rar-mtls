import dotenv from 'dotenv'
import pkg from 'node-jose';
const { JWK } = pkg;

import { random, setEnvValue, generateKeyPair, __dirname } from './helpers.js';
import { createCASignedClientCert, createSelfSignedCerts } from './MTLS/helpers.js'
import { ManagementClient} from 'auth0';
import fs from 'fs';

dotenv.config(`${__dirname}/.env`)


var mgmtClient = new ManagementClient({
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.MGMT_CLIENT_ID,
  clientSecret: process.env.MGMT_CLIENT_SECRET
});

//default
var callbackUrl = "http://127.0.0.1:8988";

var pkjwtClientId = "";
var resourceIdentifier = process.env.AUD  || "";
var nonHRIResourceIdentifier = process.env.NON_HRI_AUD || "";
var jweAccessTokenResourceIdentifier = process.env.JWE_API_AUD || "";
var rwaClientId = "";
var clients = [];

(async() => {
    try {
        await createResourceServerForNonHRIFlows();
        await createResourceServer();
        await createJWEAccessTokenResourceServer();
        await createMTLSSelfSignedCertClient();
        await createMTLSSelfSignedCertClientWithCBAT();
        await wait(3000);
        await createMTLSCASignedCertClient();
        await createMTLSCASignedCertClientWithCBAT();
        await createPrivateKeyJwtClient();
        await wait(3000);
        await createNativeClient();
        await createSpaClient();
        await createRegularWebAppClient();
        await wait(3000);
        await createRWARSClientGrant();
        await createPkJWTRSClientGrant();
        await wait(3000);
        await createJARClientClientSecret();
        await createJARClientWithPrivateKeyJwtAuth();
        await enableUserConnectionForClients(clients,process.env.CONNECTION_NAME);
        await setCustomizedConsentPromptToRenderAuthorizationDetails();
         
        
    } catch (error) {
        console.log(error);
        console.log(error.originalError);
    }

})();

async function createMTLSSelfSignedCertClient(){

  const clientName = `MTLS_AUTHZ_CODE_Self_Signed_Cert_${random()}`;

  var paths = createSelfSignedCerts(clientName);

    if(paths === null) { 
      console.log("Could not create mtls client because certs could not be created"); 
      return;
    }
    var mTLSSelfSignedClientTemplate = `
    {
      "is_token_endpoint_ip_header_trusted": false,
         "name": "${clientName}",
         "is_first_party": true,
         "oidc_conformant": true,
         "sso_disabled": false,
         "cross_origin_auth": false,
         "refresh_token": {
           "expiration_type": "non-expiring",
           "leeway": 0,
           "infinite_token_lifetime": true,
           "infinite_idle_token_lifetime": true,
           "token_lifetime": 31557600,
           "idle_token_lifetime": 2592000,
           "rotation_type": "non-rotating"
         },
         "callbacks": [
          "${callbackUrl}", "https://jwt.io", "http://localhost:3750/resume-transaction"
         ],
         "native_social_login": {
           "apple": {
             "enabled": false
           },
           "facebook": {
             "enabled": false
           }
         },
         "jwt_configuration": {
           "alg": "RS256",
           "lifetime_in_seconds": 36000,
           "secret_encoded": false
         },
         "client_aliases": [],
         "app_type": "regular_web",
         "grant_types": [
           "authorization_code",
           "implicit",
           "refresh_token",
           "client_credentials"
         ],
         "client_authentication_methods": {
               "self_signed_tls_client_auth": {
           "credentials": [{ 
             "name": "ss_cert", 
             "credential_type": "x509_cert", 
             "pem": ${JSON.stringify(fs.readFileSync(paths.clientCertificatePath).toString('utf8'))}
           }]
         }
         }
       }
    
`;

const client = (await mgmtClient.clients.create(JSON.parse(mTLSSelfSignedClientTemplate))).data;
console.log(`Created client with ID: ${client.client_id} & Name: ${client.name}`);
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED", client.client_id)
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED_REDIRECT_URI", callbackUrl);
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED_CERT_PATH", paths.clientCertificatePath)
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED_PRIVATEKEY_PATH", paths.clientPrivateKeyPath)
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED_PFX_PATH", paths.pfxPath)
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED_PFX_PWD", "Auth0Dem0");
await createClientGrant(client.client_id,process.env.AUD,process.env.AUD_SCOPES.split(" "))
clients.push(client.client_id);

}


async function  createMTLSSelfSignedCertClientWithCBAT(){

  const clientName = `MTLS_AUTHZ_CODE_Self_Signed_Cert_With_CBAT${random()}`;

  var paths = createSelfSignedCerts(clientName);

    if(paths === null) { 
      console.log("Could not create mtls client because certs could not be created"); 
      return;
    }
    var mTLSSelfSignedClientTemplate = `
    {
      "is_token_endpoint_ip_header_trusted": false,
         "name": "${clientName}",
         "callbacks": [
          "${callbackUrl}", "https://jwt.io"
         ],
         "native_social_login": {
           "apple": {
             "enabled": false
           },
           "facebook": {
             "enabled": false
           }
         },
         "jwt_configuration": {
           "alg": "RS256",
           "lifetime_in_seconds": 36000,
           "secret_encoded": false
         },
         "client_aliases": [],
         "app_type": "regular_web",
         "grant_types": [
           "authorization_code",
           "implicit",
           "refresh_token",
           "client_credentials"
         ],
         "client_authentication_methods": {
               "self_signed_tls_client_auth": {
           "credentials": [{ 
             "name": "ss_cert", 
             "credential_type": "x509_cert", 
             "pem": ${JSON.stringify(fs.readFileSync(paths.clientCertificatePath).toString('utf8'))}
           }]
         }  
         }
       }
    
`;

const client = (await mgmtClient.clients.create(JSON.parse(mTLSSelfSignedClientTemplate))).data;
console.log(`Created client with ID: ${client.client_id} & Name: ${client.name}`);
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED_CBAT", client.client_id)
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED_REDIRECT_URI_CBAT", callbackUrl);
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED_CERT_PATH_CBAT", paths.clientCertificatePath)
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED_PRIVATEKEY_PATH_CBAT", paths.clientPrivateKeyPath)
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED_PFX_PATH_CBAT", paths.pfxPath)
setEnvValue("MTLS_CLIENT_ID_SELFSIGNED_PFX_PWD_CBAT", "Auth0Dem0");
await createClientGrant(client.client_id,process.env.AUD,process.env.AUD_SCOPES.split(" "))
clients.push(client.client_id);

}

async function createMTLSCASignedCertClientWithCBAT(){

  const clientName = `MTLS_AUTHZ_CODE_CASigned_WITH_CBAT_${random()}`;

  var paths = createCASignedClientCert(clientName);

    if(paths === null) { 
      console.log("Could not create mtls client because certs could not be created"); 
      return;
    }
    var mTLSCASignedClientWithCBATTemplate = `
    {
      "is_token_endpoint_ip_header_trusted": false,
         "name": "${clientName}",
         "is_first_party": true,
         "oidc_conformant": true,
         "sso_disabled": false,
         "cross_origin_auth": false,
         "refresh_token": {
           "expiration_type": "non-expiring",
           "leeway": 0,
           "infinite_token_lifetime": true,
           "infinite_idle_token_lifetime": true,
           "token_lifetime": 31557600,
           "idle_token_lifetime": 2592000,
           "rotation_type": "non-rotating"
         },
         "callbacks": [
          "${callbackUrl}", "https://jwt.io", "http://localhost:3750/resume-transaction"
         ],
         "native_social_login": {
           "apple": {
             "enabled": false
           },
           "facebook": {
             "enabled": false
           }
         },
         "jwt_configuration": {
           "alg": "RS256",
           "lifetime_in_seconds": 36000,
           "secret_encoded": false
         },
         "client_aliases": [],
         "app_type": "regular_web",
         "grant_types": [
           "authorization_code",
           "implicit",
           "refresh_token",
           "client_credentials"
         ],
         "client_authentication_methods": {
               "tls_client_auth": {
           "credentials": [{ 
             "name": "client_with_token_binding", 
             "credential_type": "cert_subject_dn", 
             "pem": ${JSON.stringify(fs.readFileSync(paths.clientCertificatePath).toString('utf8'))}
           }]
         }
         }

       }
    
`;

const client = (await mgmtClient.clients.create(JSON.parse(mTLSCASignedClientWithCBATTemplate))).data;
console.log(`Created client with ID: ${client.client_id} & Name: ${client.name}`);
setEnvValue("MTLS_CLIENT_ID_CASIGNED_CBAT", client.client_id)
setEnvValue("MTLS_CLIENT_ID_CASIGNED_REDIRECT_URI_CBAT", callbackUrl);
setEnvValue("MTLS_CLIENT_ID_CASIGNED_CERT_PATH_CBAT", paths.clientCertificatePath)
setEnvValue("MTLS_CLIENT_ID_CASIGNED_PRIVATEKEY_PATH_CBAT", paths.clientPrivateKeyPath)
setEnvValue("MTLS_CLIENT_ID_CASIGNED_PFX_PATH_CBAT", paths.pfxPath)
setEnvValue("MTLS_CLIENT_ID_CASIGNED_PFX_PWD_CBAT", "Auth0Dem0");
await createClientGrant(client.client_id,process.env.AUD,process.env.AUD_SCOPES.split(" "))
clients.push(client.client_id);

}


async function createMTLSCASignedCertClient(){

  const clientName = `MTLS_AUTHZ_CODE_CASigned_${random()}`;

  var paths = createCASignedClientCert(clientName);

    if(paths === null) { 
      console.log("Could not create mtls client because certs could not be created"); 
      return;
    }
    var mTLSCASignedClientTemplate = `
    {
      "is_token_endpoint_ip_header_trusted": false,
         "name": "${clientName}",
         "is_first_party": true,
         "oidc_conformant": true,
         "sso_disabled": false,
         "cross_origin_auth": false,
         "refresh_token": {
           "expiration_type": "non-expiring",
           "leeway": 0,
           "infinite_token_lifetime": true,
           "infinite_idle_token_lifetime": true,
           "token_lifetime": 31557600,
           "idle_token_lifetime": 2592000,
           "rotation_type": "non-rotating"
         },
         "callbacks": [
          "${callbackUrl}", "https://jwt.io", "http://localhost:3750/resume-transaction"
         ],
         "native_social_login": {
           "apple": {
             "enabled": false
           },
           "facebook": {
             "enabled": false
           }
         },
         "jwt_configuration": {
           "alg": "RS256",
           "lifetime_in_seconds": 36000,
           "secret_encoded": false
         },
         "client_aliases": [],
         "app_type": "regular_web",
         "grant_types": [
           "authorization_code",
           "implicit",
           "refresh_token",
           "client_credentials"
         ],
         "client_authentication_methods": {
               "tls_client_auth": {
           "credentials": [{ 
             "name": "casigned_cert_mtls_1", 
             "credential_type": "cert_subject_dn", 
             "pem": ${JSON.stringify(fs.readFileSync(paths.clientCertificatePath).toString('utf8'))}
           }]
         }
         }
       }
    
`;

const client = (await mgmtClient.clients.create(JSON.parse(mTLSCASignedClientTemplate))).data;
console.log(`Created client with ID: ${client.client_id} & Name: ${client.name}`);
setEnvValue("MTLS_CLIENT_ID_CASIGNED", client.client_id)
setEnvValue("MTLS_CLIENT_ID_CASIGNED_REDIRECT_URI", callbackUrl);
setEnvValue("MTLS_CLIENT_ID_CASIGNED_CERT_PATH", paths.clientCertificatePath)
setEnvValue("MTLS_CLIENT_ID_CASIGNED_PRIVATEKEY_PATH", paths.clientPrivateKeyPath)
setEnvValue("MTLS_CLIENT_ID_CASIGNED_PFX_PATH", paths.pfxPath)
setEnvValue("MTLS_CLIENT_ID_CASIGNED_PFX_PWD", "Auth0Dem0");
await createClientGrant(client.client_id,process.env.AUD,process.env.AUD_SCOPES.split(" "))
clients.push(client.client_id);

}




async function createPrivateKeyJwtClient(){

  var pks = generateKeyPair();

    var pkJwtClientTemplate = `
{
    "is_token_endpoint_ip_header_trusted": false,
    "name": "PKJWT_CLIENT${random()}",
    "is_first_party": true,
    "oidc_conformant": true,
    "sso_disabled": false,
    "cross_origin_auth": false,
    "refresh_token": {
      "expiration_type": "non-expiring",
      "leeway": 0,
      "infinite_token_lifetime": true,
      "infinite_idle_token_lifetime": true,
      "token_lifetime": 31557600,
      "idle_token_lifetime": 2592000,
      "rotation_type": "non-rotating"
    },
    "callbacks": [
      "${callbackUrl}", "https://jwt.io", "http://localhost:3750/resume-transaction"
    ],
    "native_social_login": {
      "apple": {
        "enabled": false
      },
      "facebook": {
        "enabled": false
      }
    },
    "jwt_configuration": {
      "alg": "RS256",
      "lifetime_in_seconds": 36000,
      "secret_encoded": false
    },
    "client_aliases": [],
    "app_type": "regular_web",
    "grant_types": [
      "authorization_code",
      "implicit",
      "refresh_token",
      "client_credentials"
    ],
    "client_authentication_methods": {
      "private_key_jwt": {
        "credentials": [
          {
            "name": "key_1",
            "credential_type": "public_key",
            "pem": ${JSON.stringify(pks.publicKey)}
          }
        ]
      }
    }
  }
`;
    
    setEnvValue("PVT_KEY", JSON.stringify(pks.privateKey));
    const client = (await mgmtClient.clients.create(JSON.parse(pkJwtClientTemplate))).data;
    console.log(`Created client with ID: ${client.client_id} & Name: ${client.name}`);
    pkjwtClientId = client.client_id;
    setEnvValue("PKJWT_CLIENT_ID", client.client_id);
    setEnvValue("PKJWT_REDIRECT_URI", callbackUrl);
    clients.push(pkjwtClientId);
    


}

async function createJARClientClientSecret(){

  var pks = generateKeyPair();

    var pkJARClientTemplate = `
{
    "is_token_endpoint_ip_header_trusted": false,
    "name": "JAR_CLIENT${random()}",
    "is_first_party": true,
    "oidc_conformant": true,
    "sso_disabled": false,
    "cross_origin_auth": false,
    "refresh_token": {
      "expiration_type": "non-expiring",
      "leeway": 0,
      "infinite_token_lifetime": true,
      "infinite_idle_token_lifetime": true,
      "token_lifetime": 31557600,
      "idle_token_lifetime": 2592000,
      "rotation_type": "non-rotating"
    },
    "callbacks": [
      "${callbackUrl}", "https://jwt.io", "http://localhost:3750/resume-transaction"
    ],
    "native_social_login": {
      "apple": {
        "enabled": false
      },
      "facebook": {
        "enabled": false
      }
    },
    "jwt_configuration": {
      "alg": "RS256",
      "lifetime_in_seconds": 36000,
      "secret_encoded": false
    },
    "client_aliases": [],
    "app_type": "regular_web",
    "grant_types": [
      "authorization_code",
      "implicit",
      "refresh_token",
      "client_credentials"
    ],
    "signed_request_object": {
        "credentials": [
          {
            "name": "key_1",
            "credential_type": "public_key",
            "pem": ${JSON.stringify(pks.publicKey)}
          }
        ]
    }
  }
`;


    
    setEnvValue("JAR_PVT_KEY", JSON.stringify(pks.privateKey));
    const client = (await mgmtClient.clients.create(JSON.parse(pkJARClientTemplate))).data;
    console.log(`Created client with ID: ${client.client_id} & Name: ${client.name}`);
    setEnvValue("PKJAR_CLIENT_ID", client.client_id)
    setEnvValue("PKJAR_CLIENT_SECRET", client.client_secret)
    setEnvValue("PKJAR_REDIRECT_URI", callbackUrl);
    clients.push(client.client_id);
    


}
async function createJARClientWithPrivateKeyJwtAuth(){

  var pksAuth = generateKeyPair();

  var pksSAR = generateKeyPair();

    var pkJwtClientTemplate = `
{
    "is_token_endpoint_ip_header_trusted": false,
    "name": "JARPKJWT_CLIENT${random()}",
    "is_first_party": true,
    "oidc_conformant": true,
    "sso_disabled": false,
    "cross_origin_auth": false,
    "refresh_token": {
      "expiration_type": "non-expiring",
      "leeway": 0,
      "infinite_token_lifetime": true,
      "infinite_idle_token_lifetime": true,
      "token_lifetime": 31557600,
      "idle_token_lifetime": 2592000,
      "rotation_type": "non-rotating"
    },
    "callbacks": [
      "${callbackUrl}", "https://jwt.io", "http://localhost:3750/resume-transaction"
    ],
    "native_social_login": {
      "apple": {
        "enabled": false
      },
      "facebook": {
        "enabled": false
      }
    },
    "jwt_configuration": {
      "alg": "RS256",
      "lifetime_in_seconds": 36000,
      "secret_encoded": false
    },
    "client_aliases": [],
    "app_type": "regular_web",
    "grant_types": [
      "authorization_code",
      "implicit",
      "refresh_token",
      "client_credentials"
    ],
    "client_authentication_methods": {
      "private_key_jwt": {
        "credentials": [
          {
            "name": "keyAuth",
            "credential_type": "public_key",
            "pem": ${JSON.stringify(pksAuth.publicKey)}
          }
        ]
      }
    },
    "signed_request_object": {
        "credentials": [
          {
            "name": "keySAR",
            "credential_type": "public_key",
            "pem": ${JSON.stringify(pksSAR.publicKey)}
          }
        ]
    }
  }
`;

    
    setEnvValue("FORJAR_TEAUTH_PVT_KEY", JSON.stringify(pksAuth.privateKey));
    setEnvValue("FORJAR_SAR_PVT_KEY", JSON.stringify(pksSAR.privateKey));
    const client = (await mgmtClient.clients.create(JSON.parse(pkJwtClientTemplate))).data;
    console.log(`Created client with ID: ${client.client_id} & Name: ${client.name}`);
    setEnvValue("PKJARJWT_CLIENT_ID", client.client_id)
    setEnvValue("PKJARJWT_REDIRECT_URI", callbackUrl);
    clients.push(client.client_id);
    


}


async function createRegularWebAppClient(){

    var regularWebAppClientTemplate = `
{
    "is_token_endpoint_ip_header_trusted": false,
    "name": "RWA_CLIENT_${random()}",
    "is_first_party": true,
    "oidc_conformant": true,
    "sso_disabled": false,
    "cross_origin_auth": false,
    "refresh_token": {
      "expiration_type": "non-expiring",
      "leeway": 0,
      "infinite_token_lifetime": true,
      "infinite_idle_token_lifetime": true,
      "token_lifetime": 31557600,
      "idle_token_lifetime": 2592000,
      "rotation_type": "non-rotating"
    },
    "allowed_clients": [],
    "callbacks": [
      "${callbackUrl}","https://jwt.io"
    ],
    "native_social_login": {
      "apple": {
        "enabled": false
      },
      "facebook": {
        "enabled": false
      }
    },
    "jwt_configuration": {
      "alg": "RS256",
      "lifetime_in_seconds": 36000,
      "secret_encoded": false
    },
    "token_endpoint_auth_method": "client_secret_post",
    "app_type": "regular_web",
    "grant_types": [
      "authorization_code",
      "implicit",
      "refresh_token",
      "client_credentials"
    ],
    "custom_login_page_on": false
  }
`;
    const client = (await mgmtClient.clients.create(JSON.parse(regularWebAppClientTemplate))).data;
    console.log(`Created client with ID: ${client.client_id} & Name: ${client.name}`);
    setEnvValue("RWA_CLIENT_ID", client.client_id)
    rwaClientId = client.client_id;
    setEnvValue("RWA_CLIENT_SECRET", client.client_secret);
    setEnvValue("RWA_REDIRECT_URI", callbackUrl)
    clients.push(client.client_id);

}


async function createNativeClient(){


  var nativeClientTemplate = `
  {
    "is_token_endpoint_ip_header_trusted": false,
    "name": "Native_Device_FLow_Test-${random()}",
    "is_first_party": true,
    "oidc_conformant": true,
    "sso_disabled": false,
    "cross_origin_auth": false,
    "refresh_token": {
      "expiration_type": "non-expiring",
      "leeway": 0,
      "infinite_token_lifetime": true,
      "infinite_idle_token_lifetime": true,
      "token_lifetime": 2592000,
      "idle_token_lifetime": 1296000,
      "rotation_type": "non-rotating"
    },
    "allowed_clients": [],
    "callbacks": [
      "${callbackUrl}", "https://jwt.io"
    ],
    "native_social_login": {
      "apple": {
        "enabled": false
      },
      "facebook": {
        "enabled": false
      }
    },
    "jwt_configuration": {
      "alg": "RS256",
      "lifetime_in_seconds": 36000,
      "secret_encoded": false
    },
    "token_endpoint_auth_method": "none",
    "app_type": "native",
    "grant_types": [
      "authorization_code",
      "implicit",
      "refresh_token",
      "urn:ietf:params:oauth:grant-type:device_code"
    ],
    "custom_login_page_on": false
  }
  `;

    const client = (await mgmtClient.clients.create(JSON.parse(nativeClientTemplate))).data;
    console.log(`Created client with ID: ${client.client_id} & Name: ${client.name}`);
    setEnvValue("NATIVE_CLIENT_ID", client.client_id)
    clients.push(client.client_id);


}

async function createSpaClient(){


  var spaClientTemplate = `
  {
    "is_token_endpoint_ip_header_trusted": false,
    "name": "SPA_Test_Client-${random()}",
    "is_first_party": true,
    "oidc_conformant": true,
    "sso_disabled": false,
    "cross_origin_auth": false,
    "refresh_token": {
      "expiration_type": "non-expiring",
      "leeway": 0,
      "infinite_token_lifetime": true,
      "infinite_idle_token_lifetime": true,
      "token_lifetime": 2592000,
      "idle_token_lifetime": 1296000,
      "rotation_type": "non-rotating"
    },
    "allowed_clients": [],
    "callbacks": [
      "${callbackUrl}", "https://jwt.io"
    ],
    "native_social_login": {
      "apple": {
        "enabled": false
      },
      "facebook": {
        "enabled": false
      }
    },
    "jwt_configuration": {
      "alg": "RS256",
      "lifetime_in_seconds": 36000,
      "secret_encoded": false
    },
    "token_endpoint_auth_method": "none",
    "app_type": "spa",
    "grant_types": [
      "authorization_code",
    "implicit",
    "refresh_token"
    ],
    "custom_login_page_on": false
  }
  `;

    const client = (await mgmtClient.clients.create(JSON.parse(spaClientTemplate))).data;
    console.log(`Created client with ID: ${client.client_id} & Name: ${client.name}`);
    setEnvValue("NON_CONFIDENTIAL_CLIENT_ID", client.client_id)
    clients.push(client.client_id);
    


}



async function createResourceServerForNonHRIFlows(){

  var resourceServerTemplate = `
  {
    "name": "YOUR_API",
    "identifier": "urn:your:api",
    "token_lifetime": 86400,
    "token_lifetime_for_web": 7200,
    "skip_consent_for_verifiable_first_party_clients": true,
    "signing_alg": "RS256",
    "scopes": [
      {
        "value": "read:all_stats",
        "description": "read all data"
      },
      {
        "value": "read:stats",
        "description": "read my own stats"
      },
      {
        "value": "upload:stats",
        "description": "Upload Stats"
      }
    ]  
  }`;


  try {
    const existingRs = await mgmtClient.resourceServers.get({id : "urn:your:api"});
    console.log("Deleting existing resource server:")
    await mgmtClient.resourceServers.delete({ id: "urn:your:api"});
    const rs = (await mgmtClient.resourceServers.create(JSON.parse(resourceServerTemplate))).data;
    console.log(`Created API with ID: ${rs.id} & Audience: ${rs.identifier}`);
    setEnvValue("NON_HRI_AUD", rs.identifier)
    nonHRIResourceIdentifier = rs.identifier;
    setEnvValue("AUD_SCOPES", "read:all_stats upload:stats");
  }
  catch(error){
      if(error.statusCode === 404){
    const rs = (await mgmtClient.resourceServers.create(JSON.parse(resourceServerTemplate))).data;
    console.log(`Created API with ID: ${rs.id} & Audience: ${rs.identifier}`);
    setEnvValue("NON_HRI_AUD", rs.identifier)
    nonHRIResourceIdentifier = rs.identifier;
    setEnvValue("AUD_SCOPES", "read:all_stats upload:stats");
      }
  }

}


async function createResourceServer(){

  var resourceServerTemplate = `
  {
    "name": "BANK_API_HRI",
    "identifier": "urn:bank:api:hri",
    "token_lifetime": 86400,
    "token_lifetime_for_web": 7200,
    "skip_consent_for_verifiable_first_party_clients": true,
    "signing_alg": "RS256",
    "consent_policy": "transactional-authorization-with-mfa",
    "authorization_details": [{"type": "payment_initiation"}, {"type": "customer_information"}, {"type": "account_information"}],
    "proof_of_possession": {
        "mechanism": "mtls",
        "required": false
    },
    "scopes": [
      {
        "value": "read:all_stats",
        "description": "read all data"
      },
      {
        "value": "read:stats",
        "description": "read my own stats"
      },
      {
        "value": "upload:stats",
        "description": "Upload Stats"
      }
    ]  
  }`;


  try {
    const existingRs = await mgmtClient.resourceServers.get({id : "urn:bank:api:hri"});
    console.log("Deleting existing resource server:")
    await mgmtClient.resourceServers.delete({ id: "urn:bank:api:hri"});
    const rs = (await mgmtClient.resourceServers.create(JSON.parse(resourceServerTemplate))).data;
    console.log(`Created API with ID: ${rs.id} & Audience: ${rs.identifier}`);
    setEnvValue("AUD", rs.identifier)
    resourceIdentifier = rs.identifier;
    setEnvValue("AUD_SCOPES", "read:all_stats upload:stats");
  }
  catch(error){
      if(error.statusCode === 404){
    const rs = (await mgmtClient.resourceServers.create(JSON.parse(resourceServerTemplate))).data;
    console.log(`Created API with ID: ${rs.id} & Audience: ${rs.identifier}`);
    setEnvValue("AUD", rs.identifier)
    resourceIdentifier = rs.identifier;
    setEnvValue("AUD_SCOPES", "read:all_stats upload:stats");
      }
  }

}


async function createJWEAccessTokenResourceServer(){

  const keystore = JWK.createKeyStore();
  const key = await keystore.generate("RSA", 4096, { use: "enc", alg: "RSA-OAEP-256" });
  const pemPrivateKey = await key.toPEM(true);
  const pemPublicKey = await key.toPEM();
  

  var resourceServerTemplate = `
  {
    "name": "JWE_ENCRYPTED_ACCESS_TOKEN_API",
    "identifier": "urn:my:api:encrypted_accessToken",
    "token_lifetime": 86400,
    "token_lifetime_for_web": 7200,
    "skip_consent_for_verifiable_first_party_clients": true,
    "signing_alg": "RS256",
    "consent_policy": "transactional-authorization-with-mfa",
    "authorization_details": [{"type": "payment_initiation"}, {"type": "customer_information"}, {"type": "account_information"}],
    "proof_of_possession": {
        "mechanism": "mtls",
        "required": false
    },    "scopes": [
      {
        "value": "read:all_stats",
        "description": "read all data"
      },
      {
        "value": "read:stats",
        "description": "read my own stats"
      },
      {
        "value": "upload:stats",
        "description": "Upload Stats"
      }
    ],
    "token_encryption":{
      "format" : "compact-nested-jwe",
      "encryption_key" : {
          "name" : "at-encryption-key",
            "alg": "RSA-OAEP-256",
            "pem" : ${JSON.stringify(pemPublicKey)}
        }

      }  
  }`
  try {
    const existingRs = await mgmtClient.resourceServers.get({id : "urn:my:api:encrypted_accessToken"});
    console.log("Deleting existing resource server:")
    await mgmtClient.resourceServers.delete({ id: "urn:my:api:encrypted_accessToken"});
    const rs = (await mgmtClient.resourceServers.create(JSON.parse(resourceServerTemplate))).data;
    console.log(`Created API with ID: ${rs.id} & Audience: ${rs.identifier}`);
    setEnvValue("JWE_API_AUD", rs.identifier)
    jweAccessTokenResourceIdentifier = rs.identifier;
    setEnvValue("AUD_SCOPES", "read:all_stats upload:stats");
    setEnvValue("JWE_PRIVATE_KEY", JSON.stringify(pemPrivateKey))
  }
  catch(error){
      if(error.statusCode === 404){
    const rs = (await mgmtClient.resourceServers.create(JSON.parse(resourceServerTemplate))).data;
    console.log(`Created API with ID: ${rs.id} & Audience: ${rs.identifier}`);
    setEnvValue("JWE_API_AUD", rs.identifier)
    jweAccessTokenResourceIdentifier = rs.identifier;
    setEnvValue("JWE_PRIVATE_KEY", JSON.stringify(pemPrivateKey))
      }
  }


}

async function createPkJWTRSClientGrant(){

  
   await mgmtClient.clientGrants.create( {
    "client_id": pkjwtClientId,
    "audience": resourceIdentifier,
    "scope" : ["read:stats", "upload:stats"]
   });

   console.log(`Created client Grant for Client with ID: ${pkjwtClientId} & API: ${resourceIdentifier}`);

   await mgmtClient.clientGrants.create( {
    "client_id": pkjwtClientId,
    "audience": jweAccessTokenResourceIdentifier,
    "scope" : ["read:stats", "upload:stats"]
   });

   console.log(`Created client Grant for Client with ID: ${pkjwtClientId} & API: ${jweAccessTokenResourceIdentifier}`);

   await mgmtClient.clientGrants.create( {
    "client_id": pkjwtClientId,
    "audience": nonHRIResourceIdentifier,
    "scope" : ["read:stats", "upload:stats"]
   });

   console.log(`Created client Grant for Client with ID: ${pkjwtClientId} & API: ${nonHRIResourceIdentifier}`);
  
}


async function createRWARSClientGrant(){

  
  await mgmtClient.clientGrants.create( {
   "client_id": rwaClientId,
   "audience": resourceIdentifier,
   "scope" : ["read:stats", "upload:stats"]
  });

  console.log(`Created client Grant for Client with ID: ${rwaClientId} & API: ${resourceIdentifier}`);

  await mgmtClient.clientGrants.create( {
    "client_id": rwaClientId,
    "audience": jweAccessTokenResourceIdentifier,
    "scope" : ["read:stats", "upload:stats"]
   });

   console.log(`Created client Grant for Client with ID: ${rwaClientId} & API: ${jweAccessTokenResourceIdentifier}`);

   await mgmtClient.clientGrants.create( {
    "client_id": rwaClientId,
    "audience": nonHRIResourceIdentifier,
    "scope" : ["read:stats", "upload:stats"]
   });

   console.log(`Created client Grant for Client with ID: ${rwaClientId} & API: ${nonHRIResourceIdentifier}`);

 
}

async function createClientGrant(clientId, audience, scopeArr){
  
  await mgmtClient.clientGrants.create( {
   "client_id": clientId,
   "audience": audience,
   "scope" : scopeArr || ["read:stats", "upload:stats"]
  });

  console.log(`Created client Grant for Client with ID: ${clientId} & API: ${resourceIdentifier}`);
 
}



async function enableUserConnectionForClients(clients,name) {
  try {
    var connection = (await mgmtClient.connections.getAll({ name })).data;
    if (connection.length > 0) {
      connection = connection[0]
      var clientsEnabled = connection.enabled_clients;
      //var clientsEnabled = [];
      clients.forEach(client => {
        clientsEnabled.push(client);
      });
      
      connection = await mgmtClient.connections.update({ id: connection.id }, { enabled_clients: clientsEnabled });
      console.log('Database connection updated for all clients!');
      return connection;
    }
    console.log('ERROR!!!!: Connection not found to be enabled');

  } catch (error) {
    console.error('Error updating user connection for clients:', error.message);
  }

}

async function setCustomizedConsentPromptToRenderAuthorizationDetails(){
  // Define the customized consent template
const customizedConsentTemplate = {
  "customized-consent": {
    "form-content": `<div class="operation-details">
  <style>
    .operation-details {
      font-size: 1em;
      margin-bottom: 20px;
      font-family: Arial, sans-serif;
    }
    .title {
      font-size: 1.3em;
      font-weight: bold;
    }
    .separator {
      margin: 10px 0;
      border-top: 1px solid #ccc;
    }
    .section {
      margin-bottom: 20px;
    }
    .label {
      font-weight: bold;
      color: #333;
    }
    .value {
      margin-left: 10px;
      color: #555;
    }
  </style>

  <div class="title">Operation Details</div>
  <hr class="separator">
  
  {% for detail in transaction.params.authorization_details %}
    <div class="section">
      <div class="label">Transaction Type</div>
      <div class="value">{{ detail.type }}</div>
    </div>
    
    {% if detail.type == 'payment_initiation' %}
      <div class="section">
        <div class="label">Amount</div>
        <div class="value">{{ detail.instructedAmount.amount }} {{ detail.instructedAmount.currency }}</div>
      </div>
      <div class="section">
        <div class="label">Recipient</div>
        <div class="value">{{ detail.creditorName }}</div>
      </div>
      <div class="section">
        <div class="label">Destination Account</div>
        <div class="value">{{ detail.creditorAccount.iban }}</div>
      </div>
      <div class="section">
        <div class="label">Remittance Information</div>
        <div class="value">{{ detail.remittanceInformationUnstructured }}</div>
      </div>
    {% elsif detail.type == 'credit_request' %}
      <div class="section">
        <div class="label">Requested Credit Amount</div>
        <div class="value">{{ detail.requestedCreditAmount }} {{ detail.requestedCreditCurrency }}</div>
      </div>
      <div class="section">
        <div class="label">Requestor</div>
        <div class="value">{{ detail.requestorName }}</div>
      </div>
      <div class="section">
        <div class="label">Purpose</div>
        <div class="value">{{ detail.purpose }}</div>
      </div>
    {% elsif detail.type == 'account_information' %}
      <div class="section">
        <div class="label">Actions</div>
        <div class="value">
          <ul>
            {% for action in detail.actions %}
              <li>{{ action }}</li>
            {% endfor %}
          </ul>
        </div>
      </div>
      <div class="section">
        <div class="label">Locations</div>
        <div class="value">
          <ul>
            {% for location in detail.locations %}
              <li>{{ location }}</li>
            {% endfor %}
          </ul>
        </div>
      </div>
    {% elsif detail.type == 'customer_information' %}
      <div class="section">
        <div class="label">Locations</div>
        <div class="value">
          <ul>
            {% for location in detail.locations %}
              <li>{{ location }}</li>
            {% endfor %}
          </ul>
        </div>
      </div>
      <div class="section">
        <div class="label">Actions</div>
        <div class="value">
          <ul>
            {% for action in detail.actions %}
              <li>{{ action }}</li>
            {% endfor %}
          </ul>
        </div>
      </div>
      <div class="section">
        <div class="label">Data Types</div>
        <div class="value">
          <ul>
            {% for datatype in detail.datatypes %}
              <li>{{ datatype }}</li>
            {% endfor %}
          </ul>
        </div>
      </div>
    {% endif %}
    <div class="separator"></div>
  {% endfor %}
</div>
`
  }
};

// Update the customized consent prompt
 const updated = await mgmtClient.prompts.updatePartials({ prompt: 'customized-consent'}, customizedConsentTemplate);
console.log("Done updating the customized consent prompt for the authorization details!");
}


function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
