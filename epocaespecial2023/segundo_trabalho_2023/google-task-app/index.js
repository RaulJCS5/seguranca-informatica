const express = require('express')
const fs = require('fs')
//const path = 'client_secret_972752476658-af5c2bsg7gplk8hl0214vulg8uju8gnr.apps.googleusercontent.com.json'
//var data = JSON.parse(fs.readFileSync(path, 'utf8'));
require('dotenv').config();
const crypto = require('crypto')
const cookieParser = require('cookie-parser');
const axios = require('axios');
const FormData = require('form-data');// more info at:
// https://github.com/auth0/node-jsonwebtoken
// https://jwt.io/#libraries
const jwt = require('jsonwebtoken');
const { url } = require('inspector');
const bodyParser = require('body-parser'); // Import body-parser

const { initEnforce, isAllowed } = require('./casbinloader.js');

const port = 3001
var STATE_STORAGE = []

// system variables where Client credentials are stored
// https://www.npmjs.com/package/dotenv npm i dotenv
const CLIENT_ID = process.env.CLIENT_ID
const CLIENT_SECRET = process.env.CLIENT_SECRET
// callback URL configured during Client registration in OIDC provider
const CALLBACK = 'callback-tasks-ee2223'

const app = express()
app.use(cookieParser());

// Add bodyParser middleware to parse request bodies
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

function loginHome() {
    return (req, resp) => {
        resp.sendFile(__dirname + "/pages/usegoogleaccount.html");
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

        //console.log('making request to token endpoint')
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

                //console.log(access_token)

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
                        const listHtml = json_response.items.map(item => `<div><a href="/list/${item.id}">${item.title}</a></div>`).join("<br></br>");

                        // Set the Content-Type header to indicate that the response is HTML
                        resp.setHeader('Content-Type', 'text/html');

                        // Send the HTML content with CSS styles as a response
                        resp.send(`
                            <!DOCTYPE html>
                            <html lang="en">
                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Task List</title>
                                <style>
                                    body {
                                        font-family: Arial, sans-serif;
                                        background-color: #f5f5f5;
                                        text-align: center;
                                        margin: 0;
                                        padding: 0;
                                    }
                                    .container {
                                        background-color: #ffffff;
                                        border-radius: 8px;
                                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                                        padding: 20px;
                                        max-width: 400px;
                                        margin: 20px auto;
                                    }
                                    h1 {
                                        color: #333333;
                                    }
                                    p {
                                        color: #333333;
                                    }
                                    a {
                                        text-decoration: none;
                                        color: #0078d4;
                                        font-weight: bold;
                                    }
                                    a:hover {
                                        text-decoration: underline;
                                    }
                                    .task-item {
                                        margin: 10px 0;
                                    }
                                </style>
                            </head>
                            <body>
                                <div class="container">
                                    <h1>Task List</h1>
                                    <div class="task-list">
                                        ${listHtml}
                                    </div>
                                    <br></br>
                                    <a href="/">Home</a>
                                    <br></br>
                                    <a href="/login">Login</a>
                                    <br></br>
                                    <a href="/logout">Logout</a>
                                </div>
                            </body>
                            </html>
                        `);
                    })
                    .catch(function (error) {
                        console.log(error)
                        resp.redirect('/error')
                    });
            })
            .catch(function (error) {
                console.log(error)
                resp.redirect('/error')
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
                        const json_response = response.data;
                        const listHtml = json_response.items.map(item => `
        <div class="task-item">
            <h1><a href="/task/${item.id}">${item.title}</a></h1>
            <p>${item.notes ? item.notes : "There's no notes for this task"}</p>
        </div>`).join("<br></br>");

                        // Set the Content-Type header to indicate that the response is HTML
                        resp.setHeader('Content-Type', 'text/html');

                        // Send the HTML content with CSS styles as a response
                        resp.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Task Details</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f5f5f5;
                    text-align: center;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    background-color: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    padding: 20px;
                    max-width: 400px;
                    margin: 20px auto;
                }
                h1 {
                    color: #333333;
                }
                p {
                    color: #333333;
                }
                a {
                    text-decoration: none;
                    color: #0078d4;
                    font-weight: bold;
                }
                a:hover {
                    text-decoration: underline;
                }
                .task-item {
                    margin: 10px 0;
                }
                form {
                    margin-top: 20px;
                    padding: 10px;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                    background-color: #f9f9f9;
                }
                label {
                    display: block;
                    font-weight: bold;
                    margin-bottom: 5px;
                }
                input[type="text"] {
                    width: 100%;
                    padding: 5px;
                    margin-bottom: 10px;
                    border: 1px solid #ccc;
                    border-radius: 3px;
                }
                input[type="submit"] {
                    background-color: #0078d4;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 5px;
                    cursor: pointer;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Task Details</h1>
                ${listHtml}
                <br></br>
                <h1>Create a new task</h1>
                <form method="post">
                    <label for="title">Title:</label><br>
                    <input type="text" id="title" name="title" value=""><br>
                    <label for="notes">Notes:</label><br>
                    <input type="text" id="notes" name="notes" value=""><br><br>
                    <input type="submit" value="Submit">
                </form>
                <br></br>
                <a href="/">Home</a>
                <br></br>
                <a href="/login">Login</a>
                <br></br>
                <a href="/logout">Logout</a>
            </div>
        </body>
        </html>
    `);
                    })
                    .catch(function (error) {
                        console.log(error)
                        resp.redirect('/error')
                    });
            }
        })
    }
}
function logout() {
    return (req, resp) => {
        STATE_STORAGE = STATE_STORAGE.filter(index => index.state != req.cookies.AuthCookie)
        resp.clearCookie("AuthCookie")
        // Clear token and email in STATE_STORAGE
        resp.redirect('https://www.google.com/accounts/Logout')
    };
}


function postTasksList() {
    return (req, resp) => {
        STATE_STORAGE.map(index => {
            if (index.state == req.cookies.AuthCookie) {
                const access_token = index.token
                //console.log(req)
                const taskData = {
                    title: req.body.title,
                    notes: req.body.notes
                };

                const url = `https://tasks.googleapis.com/tasks/v1/lists/${req.params.id}/tasks`;
                axios.post(url, taskData, {
                    headers: {
                        Authorization: `Bearer ${access_token}`,
                        'Content-Type': 'application/json'
                    },
                }).then(function (response) {
                    resp.redirect(`/list/${req.params.id}`)
                })
                    .catch(function (error) {
                        console.log(error)
                        resp.redirect('/error')
                    });

            }
        })
    }
}

function authorizationMiddleware(req, resp, next) {
    if (req.cookies.AuthCookie) {
        STATE_STORAGE.map(index => {
            if (index.state == req.cookies.AuthCookie) {
                console.log("next")
                next()
            }
        })
    } else {
        console.log("redirect for login")
        resp.redirect('/login')
    }
}

function filterMethodToAction(method) {
    switch (method) {
        case "GET":
            return "read"
        case "POST":
            return "write"
        case "PUT":
            return "update"
        case "DELETE":
            return "delete"
        default:
            return "read"
    }
}

const casbinRBAC = (req, resp, next) => {
    if (req.cookies.AuthCookie) {
        STATE_STORAGE.map(index => {
            if (index.state == req.cookies.AuthCookie) {
                const userEmail = index.email
                const { path: resourceId } = req;
                const requestedAction = filterMethodToAction(req.method)

                initEnforce(userEmail, resourceId, requestedAction)
                    .then(allowed => {
                        isAllowed(allowed)
                        if (allowed.res) {
                            next()
                        }
                        else {
                            resp.redirect('/unauthorized')
                        }
                    })
            }
        })
    }
}


app.get('/', loginHome())

// More information at:
//      https://developers.google.com/identity/protocols/OpenIDConnect

app.get('/login', loginRedirect())


app.get('/' + CALLBACK, loginCallback())

app.get('/list/:id', authorizationMiddleware, casbinRBAC, getTasksList())

app.get('/error', (req, resp) => {
    // Send the error.html file as the response
    resp.sendFile(__dirname + "/pages/error.html");
});

app.post('/list/:id', authorizationMiddleware, casbinRBAC, postTasksList())

app.get('/unauthorized', (req, resp) => {
    // Send the unauthorized.html file as the response
    resp.sendFile(__dirname + "/pages/unauthorized.html");
});

app.get('/logout', logout());

app.listen(port, (err) => {
    if (err) {
        return console.log('something bad happened', err)
    }
    console.log(`server is listening on http://localhost:${port}/`)
})
