# Auth0 authentication samples using various flows using the node openid-client library

## Pre requisites
- node & npm installed
- An Auth0 tenant
- Rename the .env.sample to .env
- Get the domain, set **DOMAIN**=`<your auth0 domain>` in the .env file
- Create a Machine to Machine appliction ( client credentials) authorized for the Auth0 Management API - See [here](https://auth0.com/docs/secure/tokens/access-tokens/get-management-api-access-tokens-for-testing) for steps on how to get these credentials
- Make sure the required scopes are given to the client for the management api - create:client create:resource_servers read:clients update:clients create:client_grants

- Make note of the client_id and client_secret for the client created above set **MGMT_CLIENT_ID** and **MGMT_CLIENT_SECRET** using the values obtained within the .env file
- Install all the npm packages using `npm install`
- Run `node helpers/bootstrap.js`
    - this will create the required applications and resource servers for the rest of the samples
- NOTE: You only have to run the bootstrap once as it sets all the required data within the .env file

## Samples
- Authorization code grant flow
- CLI Authorization code grant flow
- Client Credentials with Private Key JWT
- Device flow
- Implicit flow
- PKCE Confidential client
- PKCE Non Confidential client
- PKCE Private Key JWT
- PAR
    - Authorization code grant flow
    - Implicit flow
    - public client ( not supported)
    - PKCE
    - PAR with custom auhtorization example
    - Private Key JWT





