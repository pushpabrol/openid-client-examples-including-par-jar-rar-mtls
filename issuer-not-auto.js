{
    issuer: 'https://secureaccess.desmaximus.com/',
    authorization_endpoint: 'https://mtls.secureaccess.desmaximus.com/authorize',
    token_endpoint: 'https://mtls.secureaccess.desmaximus.com/oauth/token',
    device_authorization_endpoint: 'https://mtls.secureaccess.desmaximus.com/oauth/device/code',
    userinfo_endpoint: 'https://mtls.secureaccess.desmaximus.com/userinfo',
    mfa_challenge_endpoint: 'https://mtls.secureaccess.desmaximus.com/mfa/challenge',
    jwks_uri: 'https://mtls.secureaccess.desmaximus.com/.well-known/jwks.json',
    registration_endpoint: 'https://mtls.secureaccess.desmaximus.com/oidc/register',
    revocation_endpoint: 'https://mtls.secureaccess.desmaximus.com/oauth/revoke',
    scopes_supported: [
      'openid',         'profile',
      'offline_access', 'name',
      'given_name',     'family_name',
      'nickname',       'email',
      'email_verified', 'picture',
      'created_at',     'identities',
      'phone',          'address'
    ],
    response_types_supported: [
      'code',
      'token',
      'id_token',
      'code token',
      'code id_token',
      'token id_token',
      'code token id_token'
    ],
    code_challenge_methods_supported: [ 'S256', 'plain' ],
    response_modes_supported: [ 'query', 'fragment', 'form_post' ],
    subject_types_supported: [ 'public' ],
    id_token_signing_alg_values_supported: [ 'HS256', 'RS256', 'PS256' ],
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      'private_key_jwt',
      'tls_client_auth',
      'self_signed_tls_client_auth'
    ],
    claims_supported: [
      'aud',            'auth_time',
      'created_at',     'email',
      'email_verified', 'exp',
      'family_name',    'given_name',
      'iat',            'identities',
      'iss',            'name',
      'nickname',       'phone_number',
      'picture',        'sub'
    ],
    request_uri_parameter_supported: false,
    request_parameter_supported: true,
    token_endpoint_auth_signing_alg_values_supported: [ 'RS256', 'RS384', 'PS256' ],
    tls_client_certificate_bound_access_tokens: true,
    pushed_authorization_request_endpoint: 'https://mtls.secureaccess.desmaximus.com/oauth/par',
    require_pushed_authorization_requests: false,
    end_session_endpoint: 'https://mtls.secureaccess.desmaximus.com/oidc/logout',
    require_signed_request_object: false,
    request_object_signing_alg_values_supported: [ 'RS256', 'RS384', 'PS256' ],
    revocation_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      'private_key_jwt',
      'tls_client_auth',
      'self_signed_tls_client_auth'
    ],
    revocation_endpoint_auth_signing_alg_values_supported: [ 'RS256', 'RS384', 'PS256' ]
  }