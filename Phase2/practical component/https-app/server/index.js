'use strict'

// Built-in HTTPS support
const https = require("https");
// Handling GET request (npm install express)
const express = require("express");
// Load of files from the local file system
var fs = require('fs');
const path = require('path')

const PORT = 4433;
const app = express();
const direcClient = 'client/index.html'
const directSSL = 'ssl/secure-server'
const cert_pem = 'secure-server_cer.pem'
const pfx_pem = 'secure-server_pfx.pem'
const cert2_pem = 'secure-server_cer2.pem'
const pfx2_pem = 'secure-server_pfx2.pem'
const ca_pem = 'CA_jks.pem'
const cert_alice2 = 'alice2_cer.pem'
const cert_alice1 = 'alice1_cer.pem'
const ca1_int_cer = 'ca1-int_cer.pem'
const ca2_int_cer = 'ca2-int_cer.pem'
const ca1_cer = 'ca1_cer.pem'
const ca2_cer = 'ca2_cer.pem'

//app.use('/',express.static(path.join(__dirname,'..',direcClient)))
// Get request for resource /
app.get("/", function (req, res) {
    if (!req.client.authorized) {
      //return res.status(401).send('Invalid client certificate authentication.');
      console.log('Without client certificate authentication.')
  }
  console.log(
      req.socket.remoteAddress
      //+ ' ' + req.socket.getPeerCertificate().subject.CN
      + ' ' + req.method
      + ' ' + req.url);
  res.sendFile(path.join(__dirname,'..',direcClient));
});

//without client authentication
// configure TLS handshake
const options = {
  // Necessary only if the server requires client certificate authentication.
  key: fs.readFileSync(path.join(__dirname,directSSL,pfx_pem)),
  cert: fs.readFileSync(path.join(__dirname,directSSL,cert_pem)),
};

//with client authentication
// configure TLS handshake
const optionsWClient = {
  // Necessary only if the server requires client certificate authentication.
  key: fs.readFileSync(path.join(__dirname,directSSL,pfx2_pem)),
  cert: fs.readFileSync(path.join(__dirname,directSSL,cert2_pem)),
  // Necessary only if the server uses a self-signed certificate.
  ca: 
    //fs.readFileSync(path.join(__dirname,directSSL,cert_alice1)),
    //fs.readFileSync(path.join(__dirname,directSSL,ca1_int_cer))
    //fs.readFileSync(path.join(__dirname,directSSL,ca1_cer))
    fs.readFileSync(path.join(__dirname,directSSL,ca_pem))
  ,
  // This is necessary only if using client certificate authentication.
  // Requesting the client to provide a certificate, to authenticate.
  requestCert: true,
  // As specified as "true", so no unauthenticated traffic
  // will make it to the specified route specified
  rejectUnauthorized: true
};

// Create HTTPS server
https.createServer(optionsWClient, app).listen(PORT, 
  function (req, res) {
      console.log(`Date->${new Date()} Server started at https://www.secure-server.edu:${PORT}`);
  }
);