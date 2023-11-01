import dotenv from 'dotenv'
import pkg from 'node-jose';
const { JWK } = pkg;

import { random, setEnvValue, generateKeyPair, __dirname } from './helpers.js';
import { createCASignedClientCert, createSelfSignedCerts } from './MTLS/helpers.js'
import auth0 from 'auth0';
import fs from 'fs';

dotenv.config(`${__dirname}/.env`)

var mgmtClient = new auth0.ManagementClient({
  domain: process.env.DOMAIN,
  clientId: process.env.MGMT_CLIENT_ID,
  clientSecret: process.env.MGMT_CLIENT_SECRET,
  scope: 'read:clients create:clients update:clients create:client_grants',
});

//default
var callbackUrl = "http://127.0.0.1:8988";

var pkjwtClientId = "";
var resourceIdentifier = process.env.AUD  || "";
var rwaClientId = "";
var clients = [];

(async() => {
    try {

        await createResourceServer();
        await createJWEAccessTokenResourceServer();
         await createMTLSSelfSignedCertClient();
         await createMTLSSelfSignedCertClientWithCBAT();
        await createMTLSCASignedCertClient();
        await createMTLSCASignedCertClientWithCBAT();
        await createPrivateKeyJwtClient();
        await createNativeClient();
        await createSpaClient();
        await createRegularWebAppClient();
        await createRWARSClientGrant();
        await createPkJWTRSClientGrant();
        await createJARClientClientSecret();
        await createJARClientWithPrivateKeyJwtAuth();
        await enableUserConnectionForClients(clients,process.env.CONNECTION_NAME);
         
        
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

const client = await mgmtClient.createClient(mTLSSelfSignedClientTemplate);
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


async function createMTLSSelfSignedCertClientWithCBAT(){

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
         },
         "access_token": {
             "tls_client_certificate_binding": true
         }
       }
    
`;

const client = await mgmtClient.createClient(mTLSSelfSignedClientTemplate);
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
         },
        "access_token": {
            "tls_client_certificate_binding": true
        }

       }
    
`;

const client = await mgmtClient.createClient(mTLSCASignedClientWithCBATTemplate);
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

const client = await mgmtClient.createClient(mTLSCASignedClientTemplate);
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
    const client = await mgmtClient.createClient(pkJwtClientTemplate);
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
    const client = await mgmtClient.createClient(pkJARClientTemplate);
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
    const client = await mgmtClient.createClient(pkJwtClientTemplate);
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
    const client = await mgmtClient.createClient(regularWebAppClientTemplate);
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

    const client = await mgmtClient.createClient(nativeClientTemplate);
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

    const client = await mgmtClient.createClient(spaClientTemplate);
    console.log(`Created client with ID: ${client.client_id} & Name: ${client.name}`);
    setEnvValue("NON_CONFIDENTIAL_CLIENT_ID", client.client_id)
    clients.push(client.client_id);
    


}


async function createResourceServer(){

  var resourceServerTemplate = `
  {
    "name": "MY_API_${random()}",
    "identifier": "urn:my:api:${random()}",
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
  }`
    const rs = await mgmtClient.createResourceServer(resourceServerTemplate)
    console.log(`Created API with ID: ${rs.id} & Audience: ${rs.identifier}`);
    setEnvValue("AUD", rs.identifier)
    resourceIdentifier = rs.identifier;
    setEnvValue("AUD_SCOPES", "read:all_stats upload:stats");


}


async function createJWEAccessTokenResourceServer(){

  const keystore = JWK.createKeyStore();
  const key = await keystore.generate("RSA", 4096, { use: "enc", alg: "RSA-OAEP-256" });
    const pemPrivateKey = await key.toPEM(true);
    const pemPublicKey = await key.toPEM();
  

  var resourceServerTemplate = `
  {
    "name": "ENCRYPTED_ACCESS_TOKEN_API",
    "identifier": "urn:my:api:encrypted_accessToken",
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
    const rs = await mgmtClient.createResourceServer(resourceServerTemplate)
    console.log(`Created API with ID: ${rs.id} & Audience: ${rs.identifier}`);
    setEnvValue("JWE_API_AUD", rs.identifier)
    setEnvValue("JWE_PRIVATE_KEY", JSON.stringify(pemPrivateKey))



}

async function createPkJWTRSClientGrant(){

  
   const pkjwtClientGrant = await mgmtClient.createClientGrant( {
    "client_id": pkjwtClientId,
    "audience": resourceIdentifier,
    "scope" : ["read:stats", "upload:stats"]
   });

   console.log(`Created client Grant for Client with ID: ${pkjwtClientId} & API: ${resourceIdentifier}`);
  
}


async function createRWARSClientGrant(){

  
  const rwaRSClientGrant = await mgmtClient.createClientGrant( {
   "client_id": rwaClientId,
   "audience": resourceIdentifier,
   "scope" : ["read:stats", "upload:stats"]
  });

  console.log(`Created client Grant for Client with ID: ${rwaClientId} & API: ${resourceIdentifier}`);
 
}

async function createClientGrant(clientId, audience, scopeArr){

  
  const rwaRSClientGrant = await mgmtClient.createClientGrant( {
   "client_id": clientId,
   "audience": audience,
   "scope" : scopeArr || ["read:stats", "upload:stats"]
  });

  console.log(`Created client Grant for Client with ID: ${rwaClientId} & API: ${resourceIdentifier}`);
 
}



async function enableUserConnectionForClients(clients,name) {
  try {
    var connection = await mgmtClient.getConnections({ name });
    if (connection.length > 0) {
      connection = connection[0]
      var clientsEnabled = connection.enabled_clients;
      console.log(connection);
      clients.forEach(client => {
        clientsEnabled.push(client);
      });
      
      connection = await mgmtClient.updateConnection({ id: connection.id }, { enabled_clients: clientsEnabled });
      console.log('Database connection updated for all clients!');
      return connection;
    }
    console.log('ERROR!!!!: Connection not found to be enabled');

  } catch (error) {
    console.error('Error updating user connection for clients:', error.message);
  }

}