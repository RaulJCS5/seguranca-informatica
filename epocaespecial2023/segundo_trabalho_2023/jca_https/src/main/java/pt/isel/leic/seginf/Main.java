package pt.isel.leic.seginf;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.SecureRandom;

public class Main {
    public static void main(String[] args) throws IOException, IOException {
        SSLSocketFactory sslFactory =
                HttpsURLConnection.getDefaultSSLSocketFactory();

        // print cipher suites avaliable at the client
        String[] cipherSuites = sslFactory.getSupportedCipherSuites();
        for (int i = 0; i < cipherSuites.length; ++i) {
            System.out.println("option " + i + " " + cipherSuites[i]);
        }

        // establish connection
        SSLSocket client = (SSLSocket) sslFactory.createSocket("docs.oracle.com", 443);
        client.startHandshake();
        SSLSession session = client.getSession();
        System.out.println("Cipher suite: " + session.getCipherSuite());
        System.out.println("Protocol version: " + session.getProtocol());
        System.out.println(session.getPeerCertificates()[0]);
    }
}