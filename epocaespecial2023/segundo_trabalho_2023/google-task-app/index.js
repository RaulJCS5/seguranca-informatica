const express = require('express')
const fs = require('fs')
const path = 'client_secret_972752476658-af5c2bsg7gplk8hl0214vulg8uju8gnr.apps.googleusercontent.com.json'
var data = JSON.parse(fs.readFileSync(path, 'utf8'));
console.log(data);
require('dotenv').config();
const crypto = require('crypto')
const cookieParser = require('cookie-parser');
const axios = require('axios');
const FormData = require('form-data');// more info at:
// https://github.com/auth0/node-jsonwebtoken
// https://jwt.io/#libraries
const jwt = require('jsonwebtoken');
const { url } = require('inspector');

const port = 3001
const STATE_STORAGE = []

// system variables where Client credentials are stored
// https://www.npmjs.com/package/dotenv npm i dotenv
const CLIENT_ID = process.env.CLIENT_ID
const CLIENT_SECRET = process.env.CLIENT_SECRET
// callback URL configured during Client registration in OIDC provider
const CALLBACK = 'callback-tasks-ee2223'

const app = express()
app.use(cookieParser());


function loginHome() {
    return (req, resp) => {
        resp.send('<a href=/login>Use Google Account</a>')
    }
}

function loginRedirect() {
    let state = crypto.randomUUID()
    STATE_STORAGE.push({ state })
    return (req, resp) => {
        resp.redirect(302,
            // authorization endpoint
            'https://accounts.google.com/o/oauth2/v2/auth?'

            // client id
            + 'client_id=' + CLIENT_ID + '&'

            // OpenID scope "openid email"
            // Google Tasks scope "https://www.googleapis.com/auth/tasks"
            // This is important because we are trying to access Google Tasks API
            + 'scope=openid%20email%20https://www.googleapis.com/auth/tasks&'

            // parameter state is used to check if the user-agent requesting login is the same making the request to the callback URL
            // more info at https://www.rfc-editor.org/rfc/rfc6749#section-10.12
            + `state=${state}&`

            // responde_type for "authorization code grant"
            + 'response_type=code&'

            // redirect uri used to register RP
            + 'redirect_uri=http://localhost:3001/' + CALLBACK)
    }
}

function loginCallback() {
    return (req, resp) => {
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

                // decode id_token from base64 encoding
                // note: method decode does not verify signature
                var jwt_payload = jwt.decode(response.data.id_token)

                const access_token = response.data.access_token

                console.log(access_token)

                axios.get(
                    // token endpoint
                    'https://tasks.googleapis.com/tasks/v1/users/@me/lists',
                    { headers: { Authorization: `Bearer ${access_token}` } }
                )
                    .then(function (response) {

                        STATE_STORAGE.map(index => {
                            if (index.state == req.query.state) {
                                index.token = access_token
                                index.email = jwt_payload.email
                                resp.cookie("AuthCookie", index.state)
                            }
                            return index
                        })
                        var json_response = response.data
                        let listHtml = json_response.items.map(item => `<div><a href = '/list/${item.id}'>${item.title}</a></div>`).join("<br></br>")
                        resp.send(listHtml)
                    })
                    .catch(function (error) {
                        console.log(error)
                        resp.send()
                    });


            })
            .catch(function (error) {
                console.log(error)
                resp.send()
            });
    }
}

function getTasksList() {
    return (req, resp) => {
        STATE_STORAGE.map(index => {
            if (index.state == req.cookies.AuthCookie) {
                axios.get(
                    // token endpoint
                    `https://tasks.googleapis.com/tasks/v1/lists/${req.params.id}/tasks`,
                    { headers: { Authorization: `Bearer ${index.token}` } }
                )
                    .then(function (response) {
                        var json_response = response.data
                        let listHtml = json_response.items.map(
                            item => 
                            `<div>
                                <h1 href = '/task/${item.id}'>${item.title}</h1>
                                    <p>${item.notes ? item.notes : "There's no notes for this task"}</p>
                            </div>`).join("<br></br>")
                        
                        listHtml += 
                        "<br></br>"+
                        "<h1>Create a new task</h1>"+
                        "<form method= 'post'>" +
                            "<label for='title'>Title:</label><br>" +
                            "<input type='text' id='title' name='title' value=''><br>" +
                            "<label for='notes'>Notes:</label><br>" +
                            "<input type='text' id='notes' name='notes' value=''><br><br>" +
                            "<input type='submit' value='Submit'>" +
                            "</form>"
                        resp.send(listHtml)
                    })
                    .catch(function (error) {
                        console.log(error)
                        resp.send()
                    });
            }
        })
    }
}

app.get('/', loginHome())

// More information at:
//      https://developers.google.com/identity/protocols/OpenIDConnect

app.get('/login', loginRedirect())


app.get('/' + CALLBACK, loginCallback())

app.get('/list/:id', getTasksList())

app.listen(port, (err) => {
    if (err) {
        return console.log('something bad happened', err)
    }
    console.log(`server is listening on http://localhost:${port}/`)
})
