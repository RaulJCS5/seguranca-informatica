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
const ca_pem = 'CA_jks.pem'
const cert_alice2 = 'alice2_cer.pem'

//app.use('/',express.static(path.join(__dirname,'..',direcClient)))
// Get request for resource /
app.get("/", function (req, res) {
  console.log(
      req.socket.remoteAddress
      //+ ' ' + req.socket.getPeerCertificate().subject.CN
      + ' ' + req.method
      + ' ' + req.url);
  res.sendFile(path.join(__dirname,'..',direcClient));
});

// configure TLS handshake
const options = {
  // Necessary only if the server requires client certificate authentication.
  key: fs.readFileSync(path.join(__dirname,directSSL,pfx_pem)),
  cert: fs.readFileSync(path.join(__dirname,directSSL,cert_pem)),
  // Necessary only if the server uses a self-signed certificate.
  ca: fs.readFileSync(path.join(__dirname,directSSL,ca_pem)), 
  // This is necessary only if using client certificate authentication.
  //requestCert: true, 
  rejectUnauthorized: true
};

// Create HTTPS server
https.createServer(options, app).listen(PORT, 
  function (req, res) {
      console.log("Server started at https://www.secure-server.edu:"+PORT);
  }
);