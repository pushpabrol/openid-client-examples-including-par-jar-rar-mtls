# Auth0 Authentication Samples Using Various Flows with the Node openid-client Library

### Samples
- Authorization Code Grant Flow
  - AUTHZ_CODE + response_mode=form_post
  - AUTHZ_CODE + JWTCA
  - AUTHZ_CODE
  - AUTHZ_CODE for CLI
- Client Credentials
  - Client Credentials using ID/Secret
  - Client Credentials using JWTCA
- Device Flow
  - Device flow
- IMPLICIT
  - Implicit flow
- PKCE
  - PKCE + client with ID/secret
  - PKCE + client with JWTCA
  - PKCE + Public Client(no secret)
- JAR
  - AUTHZ_CODE + JAR + client with ID/secret
  - AUTHZ_CODE + JAR + PAR + client with ID/secret
  - AUTHZ_CODE + JAR + PAR + client with JWTCA
  - PKCE + JAR + client with ID/secret
  - PKCE + JAR + JWTCA
  - AUTHZ_CODE + JAR +  client with JWTCA
- PAR
  - AUTHZ_CODE + PAR +  client with ID/secret
  - Implicit + PAR + client with ID/secret
  - PKCE + PAR + client with ID/secret
  - PKCE + PAR + client with JWTCA
  - PKCE + PAR + public client (no secret, so not supported)
  - PAR + custom RAR + Implicit flow + client with ID/secret
  - AUTHZ_CODE + PAR + client with JWTCA
  - RAR + PAR + Implicit flow
  - PKCE + PAR + client with ID/secret


## SETUP

### Prerequisites
- Node.js and npm installed
- An Auth0 tenant
- Rename the `.env.sample` file to `.env`
- Set **DOMAIN**=`<your Auth0 domain>` in the `.env` file
- Create a Machine-to-Machine Application (Client Credentials) authorized for the Auth0 Management API. Follow the steps [here](https://auth0.com/docs/secure/tokens/access-tokens/get-management-api-access-tokens-for-testing) to obtain these credentials.
- Ensure that the required scopes are assigned to the client for the Management API: `create:client`, `create:resource_servers`, `read:clients`, `update:clients`, `create:client_grants`
- Note down the `client_id` and `client_secret` for the client created above. Set **MGMT_CLIENT_ID** and **MGMT_CLIENT_SECRET** with the obtained values in the `.env` file.
- Set the name of the Auth0 connection to be enabled for each client for user authentication in the `.env` file:
  - Set **CONNECTION_NAME**=`<name of the connection>`
- Install all the npm packages using `npm install`
- Run `node helpers/bootstrap.js`
  - This will create the necessary applications and resource servers for the rest of the samples.
- **Note**: You only need to run the bootstrap once, as it sets all the required data in the `.env` file.
- **Note**: The connection name you set at **CONNECTION_NAME** should be a valid connection in the tenant. It will set up the connection to be enabled for each client, allowing users to authenticate.

### Cleanup Script
- There is a script file named `auth0Cleanup.js` under the `helpers` folder. Running this script will delete the applications and resource servers created in Auth0. This acts as a reset step in case you want to delete all data and start fresh with the bootstrapping process. To run the cleanup, use `node helpers/auth0Cleanup.js`


### How to Test?
Run your sample using Node.js. For example: `node FOLDER/file.js`
Example: `node PAR/par-with-private-key-jwt.js`

**Note**: Most of the examples above use `https://jwt.io` as a callback URL to receive either the token response directly or use a server listening at `http://127.0.0.1:8988` for the authorization code.

**Note**: Contact your Auth0 representative or solutions engineers to ensure that required features such as PAR, JAR, RAR are enabled for your Auth0 tenant!
