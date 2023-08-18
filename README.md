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
- NOTE: Make sure the correct connections are enabled at each application you created. To enable or disable connections go to the auth0 management console and edit.
### Cleanup Script
- There is also a script file named auth0Cleanup.js under the helpers folder. Running this script will delete the applications and the resource server created in auth0. This acts as a reset step incase you want to delete all data and start from scratch with the bootstrapping process. To run the cleanup use `node helpers/auth0Cleanup.js`

## Samples
- Authorization code grant flow
- Client Credentials
- Device Flow
- PKCE
- PAR & PAR with RAR
    - Authorization code grant flow
    - Implicit flow
    - public client ( not supported)
    - PKCE
    - PAR with custom auhtorization example
    - Private Key JWT

- JAR
- IMPLICIT


### How to test?
Run your sample using node, example: - `node FOLDER/file.js` 
Example: `node PAR/par-with-private-key-jwt.js`

### NOTE: Majority of the examples above use https://jwt.io as a callback url to recieve either the token response directly or use a server listening at http://127.0.0.1:8988 listening for the authorization code.


### NOTE: You will need to contact your Auth0 rep or solutions engineers etc to make sure the required feature such as PAR, JAR, RAR are enabled for your auth0 tenant!




