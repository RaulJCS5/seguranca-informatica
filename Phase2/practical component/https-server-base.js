// Built-in HTTPS support
const https = require("https");
// Handling GET request (npm install express)
const express = require("express");
// Load of files from the local file system
var fs = require('fs'); 

const PORT = 4433;
const app = express();

// Get request for resource /
app.get("/", function (req, res) {
    console.log(
        req.socket.remoteAddress
        //+ ' ' + req.socket.getPeerCertificate().subject.CN
        + ' ' + req.method
        + ' ' + req.url);
    res.send("<html><body>Secure Hello World with node.js</body></html>");
});


// configure TLS handshake
const options = {
    key: fs.readFileSync('secure-server_pfx.pem'),
    cert: fs.readFileSync('secure-server_cer.pem'),
    ca: fs.readFileSync('CA_jks.pem'), 
    requestCert: true, 
    rejectUnauthorized: true
};

// Create HTTPS server
https.createServer(options, app).listen(PORT, 
    function (req, res) {
        console.log("Server started at port " + PORT);
    }
);
/*
 const options = {
   hostname: 'encrypted.google.com',
   port: 443,
   path: '/',
   method: 'GET'
 };
 const options = {
       hostname: 'encrypted.google.com',
       port: 443,
       path: '/',
       method: 'GET',
       key: fs.readFileSync('secure-server_pfx.pem'),
       cert: fs.readFileSync('secure-server_cer.pem'),
     };
     options.agent = new https.Agent(options);

 const req = https.request(options, (res) => {
   console.log('statusCode:', res.statusCode);
   console.log('headers:', res.headers);

   res.on('data', (d) => {
     process.stdout.write(d);
   });
 });

 req.on('error', (e) => {
   console.error(e);
 });
 req.end();*/
