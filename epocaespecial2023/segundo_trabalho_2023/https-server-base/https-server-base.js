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
        + ' ' + req.socket.getPeerCertificate().subject.CN
        + ' ' + req.method
        + ' ' + req.url);
    res.send("<html><body>Secure Hello World with node.js</body></html>");
});


// configure TLS handshake
const options = {
    key: fs.readFileSync('secure-server_pfx.pem'),
    cert: fs.readFileSync('secure-server-certificate.pem'),
    ca: [fs.readFileSync('CA1-int-certificate.pem'),fs.readFileSync('CA1-certificate.pem'),], 
    requestCert: true, 
    rejectUnauthorized: true
};

// Create HTTPS server
https.createServer(options, app).listen(PORT, 
    function (req, res) {
        console.log("Server started at port " + PORT);
    }
);

// Convert a DER file (.crt .cer .der) to PEM
// openssl x509 -inform der -in secure-server.cer -out secure-server-certificate.pem
// openssl x509 -inform der -in CA1-int.cer -out CA1-int-certificate.pem
// openssl x509 -inform der -in CA1.cer -out CA1-certificate.pem

// Convert a PKCS#12 file (.pfx .p12) containing a private key and certificates to PEM
// openssl pkcs12 -in secure-server.pfx -out secure-server-private.pem -nodes
