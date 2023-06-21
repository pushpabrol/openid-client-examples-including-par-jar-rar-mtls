import  KJUR from 'jsrsasign'
import {v4 as uuid} from 'uuid'


function getSignedJWT() {


var iss = "xLRbIZUQ0CrJIMK3UCuBYJjs9rmvGC8s";
var privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAh9FAeUZ/W3Fr9USgg5MFYqDoy7sYNyH0Eej1xwyf66HMTVW/
v3ff8gmsSher9d1hefgAO229K9Bx+ddoO5M0O9v+ejQc8rUUwkqy21XtHjwoewg7
kUMbVeFWHAVLUkCrifdgh3EPvbX2vbwxg7kJystLCZYaogF/efnIE2mnWeZhBsuV
eVSMZYb/cJCU/u6M2dFcB86TIJz7wOanliiDx8hU2CG0bqT1G6In0eLN+gT+En60
vrMyyaTUYaE3lwjrdkXnq5OjcO724YnhazgoJBWWeU5p7G3Caayowp0uL7PhEEHX
WAAJdPqTP2vFnQyySpv7OpFCmvubnP/Xu8PjjQIDAQABAoIBAGmN8WPPrG9vKQ5H
tdBMVSUgFY0w7VL76mp4+Xsnjqpc5yE7gXjXO48qgWJcH2NIGNfoLJYDZcBFki8w
gGu8rh3Pjml/Uvg2T9nooDTjBRQ4gOWNsm3lD7uhE4FXhAB7DlZ9keHxtuAkKY2w
U3MiPkAD21+p7yz1qRMtU5fyxwOQYq1H+xjG8WOzsB5c6T79CE+gB6WSB008e4mm
NR/U8li9LeGZDOCrVewsA5pyDW9aFkp77YFnUQQD1u5nufhivfkUXHycJ3jC3yiP
TOYJVq/Jxe/LeRWt7yWFhmDa0OdK6tx56mNMJf3uyqpZqJnU7uUnxYUnoZ3V1GVm
SKBS8QECgYEA82HLdQ5cwZz/lhhRE7aqlEmdRaodo+qXW/GqXLZYYEfzMEp81VaC
BtstjOq1+rY0/YUVE5vZMPyeaGDiVEhxDMKWNH3dLgJd8p6leWDRmRRE3wGj0TEt
Cd9jVBVZbYmrZknLQtO3sORVG3jyhfsHBZcAu8x5lgcaWxKmilIFpu0CgYEAjtvX
lYhR+tb6h8199iE9ytesTjprZheimx/gMKr8/aTtfHTClVzVECujPQ2bQnSeU2uJ
F8vD2Y4dLOTROKZbCsgkE6KEL+f3KF8qtE9ob1n1TFAaku+CW5R3SkAxKDnkZsEX
Zr4rsM2UOa1NHVExz2575suAg9QgXm33zkT7+yECgYByxFLkx/kFc7syVBUnbqPR
eUUobKe9fAoT2Um0nmfePw92XimvkDOQeBpqsONPbkxeoDroHD220+j+33Dava5R
jhC2gAOkhok2t4jgS7+Kp/wyDNvq8X2DgkucgtTAyoKAoZuvz5Z3W7SmV8pFU7Jj
+GjoJevPy1mqSIkwAK2ZoQKBgEvMf826f+z9Jf7qXHw81QGMf8MeIiAQSFnQhu6r
uwKGAPA5L4l6sR4cWUeqsYeIQv12IE588lS7n+VTH2PUeJf265VzdHnKtYw5Onpj
a8ExVQMBuafe5ybaVpUSDEMQvIx8xYLhQmNUIOKdfj4g97HdKGaj8XOBGQ+hf4t1
dNGhAoGBAJ7/SUO+w0nHB56V5tMoQ61pOmVl6jRVOVpQyU5S7wK5jzcT3UnF6bkF
+VQu/UlsJrzzbDrYHOGQeAGDh6a5uufv+VlT4EHO9jKY9oGz0UPA4Nl1E992CFVc
lZIqFO+ejohHR2f9Pg2aAeWZ1Lr9uDCdTaQsXTNmC++zCB7rqhEy
-----END RSA PRIVATE KEY-----`;
var auth0Domain = "oidc-tests.auth0.com";

const header = {"alg" : "RS256", "kid" : "wA4Ze2OwT4bJNEeHUQ6sYqExaAqbnECs7AJCUCaP7cI"};

  const current = KJUR.jws.IntDate.get('now');
  const expireOneMinute = current + 60; // 5 sec

const claimSet =
{
  "iss": iss,
  "sub": iss ,
  "aud":`https://${ auth0Domain }/`,
  "exp":expireOneMinute,
  "iat": current,
  "jti" : uuid()
}

//console.log(`header: ${ JSON.stringify(header)}`);
//console.log(`claim set: ${ JSON.stringify(claimSet) }`);
//console.log(`Private Key: ${ privateKey }`);

//  let jws = new KJUR.jws.JWS(); 
var jwt =  KJUR.jws.JWS.sign(null, header, claimSet, privateKey);
//console.log(jwt);
return jwt;


}

export default getSignedJWT;