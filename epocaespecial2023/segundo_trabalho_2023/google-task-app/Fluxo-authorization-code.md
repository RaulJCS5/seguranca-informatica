# Fluxo do tipo Authorization Code

```
Browser                 Client (app web)                Authorization server Ex: Google, Github, Auth0, ...
|                       |                               |
|---- Login start ----->|                               |
|<-- 302 Redirect to ---|                               |
| authorization endpoint|                               |
| + scope=openid        |                               |
|
|---- GET authorization endpoint + scope=openid ------->|-----------------------|
|<----------------------------------------------------->|Authorization endpoint |
|<---- 302 Redirect callback URL + code ----------------|-----------------------|
|                       |
| --GET callback+code ->|
|                       |
|                       |       POST /token             |---------------|
|                       |------ + code + client_id ---->|               |
|                       |       + client_secret         |Token endpoint |
|                       |                               |               |
|                       |<-- Access Token + ID Token ---|---------------|
|                       |                               |
|<----  Login end   ----|                               |-----------------------|
|   Authenticator       |-- GET/user_info+access token->|                       |
|   (ex: userid+hmac)   |                               |UserInfo Endpoint      |
|                       |<-------- User Info -----------|                       |
|                       |                               |-----------------------|
|                       |                               |
|                       |                               |
```