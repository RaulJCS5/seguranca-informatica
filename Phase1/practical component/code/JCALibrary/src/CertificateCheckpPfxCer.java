import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class CertificateCheckpPfxCer {
    private static final String keystoreFile = "Alice_1.pfx";
    private static final String certificateFile = "Alice_1.cer";
    private static final String password = "changeit";
    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        FileInputStream input = new FileInputStream(keystoreFile);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(input, password.toCharArray());
        input.close();
        Enumeration<String> entries = keyStore.aliases();
        PrivateKey privateKey = null;
        X509Certificate cert = null;
        PublicKey publicKey=null;
        while (entries.hasMoreElements()) {
            String alias = entries.nextElement();
            cert = (X509Certificate) keyStore.getCertificate(alias);
            publicKey = cert.getPublicKey();
            privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        }

        FileInputStream inFile = new FileInputStream(String.valueOf(Paths.get(certificateFile)));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(inFile);
        if (certificate.equals(cert)){
            System.out.println("igual");
        }
    }
}
