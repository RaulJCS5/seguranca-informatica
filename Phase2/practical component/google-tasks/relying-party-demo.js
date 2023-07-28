const express = require('express')
const cookieParser = require('cookie-parser');
const axios = require('axios');
const FormData = require('form-data');// more info at:
// https://github.com/auth0/node-jsonwebtoken
// https://jwt.io/#libraries
const jwt = require('jsonwebtoken');
const casbin = require('casbin');
const { newEnforcer } = casbin;

const port = 3001

// system variables where Client credentials are stored
const CLIENT_ID = '1081673935269-pb0fja1uhjduf1144g521p86iuimgagc.apps.googleusercontent.com'
const CLIENT_SECRET = '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'
// callback URL configured during Client registration in OIDC provider
const CALLBACK = 'callback'

const app = express()
app.use(cookieParser());

app.get('/', (req, resp) => {
    resp.send('<a href=/login>Use Google Account</a>')
})

// More information at:
//      https://developers.google.com/identity/protocols/OpenIDConnect

app.get('/login', (req, resp) => {
    resp.redirect(302,
        // authorization endpoint
        'https://accounts.google.com/o/oauth2/v2/auth?'

        // client id
        + 'client_id=' + CLIENT_ID + '&'

        // OpenID scope "openid email"
        + 'scope=openid%20email&'

        // parameter state is used to check if the user-agent requesting login is the same making the request to the callback URL
        // more info at https://www.rfc-editor.org/rfc/rfc6749#section-10.12
        + 'state=value-based-on-user-session&'

        // responde_type for "authorization code grant"
        + 'response_type=code&'

        // redirect uri used to register RP
        + 'redirect_uri=http://localhost:3001/' + CALLBACK)
})

function addDays(days) {
    var result = new Date();
    result.setDate(result.getDate() + days);
    return result;
}

app.get('/' + CALLBACK, (req, resp) => {
    //
    // TODO: check if 'state' is correct for this session
    //

    console.log('making request to token endpoint')
    // content-type: application/x-www-form-urlencoded (URL-Encoded Forms)
    const form = new FormData();
    form.append('code', req.query.code);
    form.append('client_id', CLIENT_ID);
    form.append('client_secret', CLIENT_SECRET);
    form.append('redirect_uri', 'http://localhost:3001/' + CALLBACK);
    form.append('grant_type', 'authorization_code');
    //console.log(form);

    axios.post(
        // token endpoint
        'https://www.googleapis.com/oauth2/v3/token',
        // body parameters in form url encoded
        form,
        { headers: form.getHeaders() }
    )
        .then(function (response) {
            // AXIOS assumes by default that response type is JSON: https://github.com/axios/axios#request-config
            // Property response.data should have the JSON response according to schema described here: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse

            //console.log(response.data)
            // decode id_token from base64 encoding
            // note: method decode does not verify signature
            var jwt_payload = jwt.decode(response.data.id_token)
            //console.log(jwt_payload)

            // cookie with access token
            resp.cookie("AccessToken", JSON.stringify(response.data.access_token), {
                httpOnly: true,
                secure: true,
                expires: addDays(30)
            });
            // cookie with id token
            resp.cookie("IdToken", JSON.stringify(response.data.id_token), {
                httpOnly: true,
                secure: true,
                expires: addDays(30)
            });
            // HTML response with the code and access token received from the authorization server
            resp.send(
                '<div> callback with code = <code>' + req.query.code + '</code></div><br>' +
                '<div> client app received access code = <code>' + response.data.access_token + '</code></div><br>' +
                '<div> id_token = <code>' + response.data.id_token + '</code></div><br>' +
                '<div> Hi <b>' + jwt_payload.email + '</b> </div><br>' +
                'Go back to <a href="/">Home screen</a>' +
                '<p><p>' +
                '<a href="/addtask">Add tasks</a>' +
                '<p><p>' +
                '<a href="/viewtasks">View tasks</a>'
            );
        })
        .catch(function (error) {
            console.log(error)
            resp.send()
        });
})

app.get('/addtask', (req, resp) => { //addtask
    resp.sendFile(__dirname + '/addtask.html');
})

app.get('/viewtasks', (req, resp) => { //viewtasks
    resp.sendFile(__dirname + '/viewtasks.html');
})

const policyFile = 'path/to/your/policy_file.conf';
const modelFile = 'path/to/your/model_file.conf';

// Create an instance of the Casbin Enforcer.
async function createEnforcer() {
    const enforcer = await newEnforcer(modelFile, policyFile);

    // Load policy rules for RBAC1 model
    const rbac1Policy = `
    p, admin, data, read
    p, premium, data, read
    p, premium, data, write
    p, free, data, read
  `;
    enforcer.loadPolicyLine(rbac1Policy);

    return enforcer;
}


app.get('/premium-route', async (req, resp) => {
    // Check access for the premium route using Casbin Enforcer
    const enforcer = await createEnforcer();
    const { user } = req; // Assuming the user object has 'role' property

    const accessAllowed = await enforcer.enforce(user.role, 'data', 'read');
    if (accessAllowed) {
        // Serve the premium route content here
        resp.send('You have access to the premium route.');
    } else {
        // Return an unauthorized response
        resp.status(403).send('You do not have access to the premium route.');
    }
});

app.listen(port, (err) => {
    if (err) {
        return console.log('something bad happened', err)
    }
    console.log(`server is listening on http://localhost:${port}`)
})