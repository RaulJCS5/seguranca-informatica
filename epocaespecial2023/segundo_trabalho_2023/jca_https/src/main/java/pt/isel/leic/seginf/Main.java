package pt.isel.leic.seginf;

import javax.net.ssl.*;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class Main {
    public static void main(String[] args) throws IOException, IOException, CertificateException, KeyStoreException, KeyManagementException, NoSuchAlgorithmException, UnrecoverableKeyException {
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // Load the certificate from resource file
        ClassLoader classLoader = Main.class.getClassLoader();
        InputStream secureServerCertInputStream = classLoader.getResourceAsStream("secure-server.cer");
        if (secureServerCertInputStream == null) {
            throw new FileNotFoundException("Certificate file not found");
        }
        // Load the certificate from resource file
        InputStream alice2PfxInputStream = classLoader.getResourceAsStream("Alice_2.pfx");
        if (alice2PfxInputStream == null) {
            throw new FileNotFoundException("Pfx file not found");
        }


        final Certificate secureServerCert = certificateFactory.generateCertificate(secureServerCertInputStream);

        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(alice2PfxInputStream, "changeit".toCharArray());
        keyStore.setCertificateEntry("secureServerCert", secureServerCert);

        //CA1-Int converter para PEM e concatener com o PEM do secure-server
        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        final TrustManager[] trustManagerArray = trustManagerFactory.getTrustManagers();

        // As linhas abaixo são para usar autenticação de cliente
        // O KeyManager é responsável por gerenciar as chaves privadas usadas pelo cliente durante o processo de autenticação.

        /*
        final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, "changeit".toCharArray());
        final KeyManager[] keyManagerArray = keyManagerFactory.getKeyManagers();
        */
        final SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");

        final SSLContext sslContext = SSLContext.getInstance("TLS");

        //passar null o primeiro argumento para não usar autenticação de cliente
        sslContext.init(null, trustManagerArray, secureRandom);

        final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        // print cipher suites avaliable at the client
        String[] cipherSuites = sslSocketFactory.getSupportedCipherSuites();
        for (int i = 0; i < cipherSuites.length; ++i) {
            System.out.println("option " + i + " " + cipherSuites[i]);
        }

        // establish connection
        SSLSocket client = (SSLSocket) sslSocketFactory.createSocket("www.secure-server.edu", 4433);
        client.startHandshake();
        SSLSession session = client.getSession();
        System.out.println("Cipher suite: " + session.getCipherSuite());
        System.out.println("Protocol version: " + session.getProtocol());
        System.out.println(session.getPeerCertificates()[0]);
    }
}