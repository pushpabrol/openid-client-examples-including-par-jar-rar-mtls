# Auth0 Authentication Samples Using Various Flows with the Node `openid-client` Library

This repository contains samples demonstrating how to use various OAuth2.0 and OIDC flows with the Node `openid-client` library and Auth0. This also includes sample for [HRI](https://auth0.com/docs/secure/highly-regulated-identity). See how [HRI](https://auth0.com/docs/secure/highly-regulated-identity#confidentiality-and-integrity-protection) helps with incerasing confidentiality and integrity protection 

## Samples Overview

### Authorization Code Grant Flow
- AUTHZ_CODE + response_mode=form_post
- AUTHZ_CODE + JWTCA
- AUTHZ_CODE
- AUTHZ_CODE for CLI

### Client Credentials Flow
- Client Credentials using ID/Secret
- Client Credentials using JWTCA

### Device Flow
- Device Flow

### Implicit Flow
- Implicit Flow

### PKCE (Proof Key for Code Exchange)
- PKCE + Client with ID/Secret
- PKCE + Client with JWTCA
- PKCE + Public Client (no secret)

### [JAR](https://auth0.com/docs/secure/highly-regulated-identity#jwt-secured-authorization-request-jar-) (JWT Secured Authorization Request) [HRI]
- AUTHZ_CODE + JAR + Client with ID/Secret
- AUTHZ_CODE + JAR + PAR + Client with ID/Secret
- AUTHZ_CODE + JAR + PAR + Client with JWTCA
- PKCE + JAR + Client with ID/Secret
- PKCE + JAR + Client with JWTCA
- AUTHZ_CODE + JAR + Client with JWTCA

### [PAR](https://auth0.com/docs/secure/highly-regulated-identity#pushed-authorization-requests-par-) (Pushed Authorization Request)
- AUTHZ_CODE + PAR + Client with ID/Secret
- Implicit + PAR + Client with ID/Secret
- PKCE + PAR + Client with ID/Secret
- PKCE + PAR + Client with JWTCA
- PKCE + PAR + Public Client (no secret, so not supported)
- PAR + Custom RAR + Implicit Flow + Client with ID/Secret
- AUTHZ_CODE + PAR + Client with JWTCA
- RAR + PAR + Implicit Flow
- PKCE + PAR + Client with ID/Secret

### [MTLS](https://auth0.com/docs/secure/highly-regulated-identity#stronger-application-authentication)
For setup for MTLS and custom domain with self-managed certificates in Auth0, see the [Custom Domain and MTLS Setup](MTLS/AUTH0_REVERSE_PROXY_SETUP/README.md).
- AUTHZ_CODE + MTLS with CA-signed cert
- Client Credentials Flow + MTLS with CA-signed cert
- PAR + AUTHZ_CODE + MTLS with CA-signed cert
- AUTHZ_CODE + MTLS with CA-signed cert + Client Bound Access Token
- Client Credentials Flow + MTLS with CA-signed cert + Client Bound Access Token
- AUTHZ_CODE + MTLS with self-signed cert
- Client Credentials Flow + MTLS with self-signed cert
- Client Credentials Flow + MTLS with self-signed cert + Client Bound Access Token
- MTLS + JAR + PAR + JWE + CBAT + Calling RS that will decrypt token + verify CBAT 

### [JWE](https://auth0.com/docs/secure/highly-regulated-identity#protect-sensitive-data-in-access-tokens) JSON Web Encryption for access tokens
(Auth0 issued access token is JWE, Resource Server in Auth0 holds the public key to encrypt the access token)
- AUTHZ_CODE + JWE Access Token

## Setup

### Prerequisites
- **Node.js and npm**: Ensure you have Node.js and npm installed.
- **Auth0 Tenant**: An active Auth0 tenant.

### Configuration Steps

1. **Rename the `.env.sample` file to `.env`**:
   ```bash
   mv .env.sample .env
   ```

2. **Configure Environment Variables**:
   - Set **DOMAIN** and **AUTH0_DOMAIN** to your Auth0 custom domain and canonical domain recpectively in the `.env` file:
     ```bash
     AUTH0_DOMAIN=<tenant>.auth0.com #auth0 canonical domain
     DOMAIN=<your Auth0 custom domain>
     ```
   - Create a Machine-to-Machine Application (Client Credentials) authorized for the Auth0 Management API. Follow [this guide](https://auth0.com/docs/secure/tokens/access-tokens/get-management-api-access-tokens-for-testing) to obtain the credentials.
   - Set **MGMT_CLIENT_ID** and **MGMT_CLIENT_SECRET** with the client ID and secret obtained from the above step in the `.env` file:
     ```bash
     MGMT_CLIENT_ID=<your management client id>
     MGMT_CLIENT_SECRET=<your management client secret>
     ```
   - Set the **CONNECTION_NAME** to the name of the Auth0 connection to be enabled for each client:
     ```bash
     CONNECTION_NAME=<name of the connection>
     ```
   - Set all the other values in the .env file
     ```bash
     # MGMT Operations ( Set all values  before running the helpers/bootstrap.js)
        AUD=urn:bank:api:hri # audience that you would want to use for the HRI API (this does not need to exist in auth0 as the bootstrapping process will create it )
        AUD_SCOPES=read:all_stats upload:stats # hard coded
        REDIRECT_URI=https://jwt.io # hard coded for testing
        JWE_API_AUD=urn:my:api:encrypted_accessToken # audience name that you would want to use for the API that expects access tokens to be encrypted (this does not need to exist in auth0 as the bootstrapping process will create it )
        NON_HRI_AUD=urn:your:api # audience name that you would want to use for the non HRI API (this does not need to exist in auth0 as the bootstrapping process will create it )
        RESOURCE_SERVER_API_FOR_TOKEN_BINDING_TESTING=https://api.yourdomain.com/mtls/protected #advanced - this is only needed for API Testing
        RESOURCE_SERVER_API_FOR_JWE_TOKEN_BINDING_TESTING=https://api.yourdomain.com/mtls/protected/jwe #advanced - this only needed for API testing
        NODE_TLS_REJECT_UNAUTHORIZED=0 # this is set to avoid node throwing errors about untrusted CA issued certs, specially behind a proxy in corporate environments!
        #NODE_EXTRA_CA_CERTS="./helpers/MTLS/CA/ca.crt" # (full path to the CA cert)this might help but if you are behind a corporate f/w, but if it eve drops then it wont work!

     ```



3. **Install Dependencies**:
   ```bash
   npm install
   ```

4. **Bootstrap the Setup**:
   - Run the bootstrap script to create the necessary applications and resource servers:
     ```bash
     node helpers/bootstrap.js
     ```
   - **Note**: Run the bootstrap script only once, as it sets up the required configurations in the `.env` file.

5. **Verify the Connection**:
   - The connection name you set at **CONNECTION_NAME** should be valid in your Auth0 tenant. This enables user authentication through the specified connection.

### Cleanup

To reset your setup and remove the applications and resource servers created in Auth0:

1. Run the cleanup script:
   ```bash
   node helpers/auth0Cleanup.js
   ```

### How to Test?

Run any sample using Node.js by specifying the folder and file name. For example:
```bash
node FOLDER/file.js
```
Example:
```bash
node PAR/par-with-private-key-jwt.js
```

**Notes**:
- Many examples use `https://jwt.io` as the callback URL to receive tokens or `http://127.0.0.1:8988` for the authorization code.
- Contact your Auth0 representative or solutions engineer to ensure required features like PAR, JAR,MTLS and RAR are enabled for your Auth0 tenant. See 
- For MTLS and access token binding some of the samples also include calling an API that is setup to be able to handle tokens containg the `x5t#S256` claim. The source code sample for such an API is out of the scope of this sample. 

## Additional Resources
For more detailed information, refer to:
- [Auth0 Documentation](https://auth0.com/docs)
- [Node `openid-client` Library](https://github.com/panva/node-openid-client)

