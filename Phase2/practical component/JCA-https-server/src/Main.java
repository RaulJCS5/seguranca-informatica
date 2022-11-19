import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class Main {
    private static final String SECURE_SERVER_CERT = "secure-server.cer";
    private static final String SECURE_SERVER_PFX = "secure-server.pfx";
    private static final String CERTIFICATE_X_509 = "X.509";
    private static final String SECURE_SERVER_CERT_ALIAS = "secureServerCertificate";
    private static final String PASSWORD = "";
    private static final String SSL_CONTEXT_TLS = "TLS";
    private static final String HOST_URL = "www.secure-server.edu";
    private static final int PORT = 4433;

    public static void main(String[] args) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_X_509);
        InputStream secureServerCertInputStream = ClassLoader.getSystemResourceAsStream(SECURE_SERVER_CERT);
        Certificate secureServerCertificate = certificateFactory.generateCertificate(secureServerCertInputStream);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(ClassLoader.getSystemResourceAsStream(SECURE_SERVER_PFX), PASSWORD.toCharArray());
        keyStore.setCertificateEntry(SECURE_SERVER_CERT_ALIAS, secureServerCertificate);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, PASSWORD.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        SecureRandom secureRandom = SecureRandom.getInstance(SecureRandom.getInstanceStrong().getAlgorithm());

        SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT_TLS);
        sslContext.init(keyManagers, trustManagers, secureRandom);

        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(HOST_URL, PORT);

        sslSocket.startHandshake();
        SSLSession session = sslSocket.getSession();
        System.out.println("Cipher suite: " + session.getCipherSuite());
        System.out.println("Protocol version: " + session.getProtocol());
        System.out.println(session.getPeerCertificates()[0]);
    }
}