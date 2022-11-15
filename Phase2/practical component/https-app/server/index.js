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
const directSSL = 'ssl'
const cert_pem = 'cert.pem'
const pfx_pem = 'key.pem'

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

const options = {
  key: fs.readFileSync(path.join(__dirname,directSSL,pfx_pem)),
  cert: fs.readFileSync(path.join(__dirname,directSSL,cert_pem))
};

// Create HTTPS server
https.createServer(options, app).listen(PORT, 
  function (req, res) {
      console.log("Server started at https://localhost:" + PORT);
  }
);