# Auth0 authentication samples using various flows using the node openid-client library

## Pre requisites
    - An Auth0 tenant
    - Rename the .env.sample to .env
    - Get the domain, set DOMAIN= in the .env file
    - Create a Machine to Machine appliction ( client credentials) authorized for the Auth0 Management API - Check steps on how to do this at https://auth0.com/docs/secure/tokens/access-tokens/get-management-api-access-tokens-for-testing
    - Make sure the required scopes are given to the client for the management api - create:client & create:resource_servers

    - Make note of the client_id and client_secret for the client created above set MGMT_CLIENT_ID and MGMT_CLIENT_SECRET using the values obtained within the .env file
    - Install all the npm packages using npm install
    - Run ` node helpers/bootstrap.js
        - this will create the required applications and resource servers for the rest of the samples
    NOTE: You only have to run 

## Samples
    - Authorization code grant flow
    - CLI Authorization code grant flow
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





