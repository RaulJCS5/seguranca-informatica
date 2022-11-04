
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;


public class Main {
    /**
     * The list of certificate needs to be in order end-entity(certificado folha), cert-int(certificado intermédios), trust-anchors(certificado auto-assinado).
     * */
    public static void main(String[] args) throws Exception {
        FileInputStream alice = new FileInputStream("end-entities/Alice_1.cer");
        FileInputStream inter = new FileInputStream("cert-int/CA1-int.cer");
        FileInputStream root = new FileInputStream("trust-anchors/CA1.cer");
        checkPathCertificate(new FileInputStream[]{alice,inter,root});
        alice.close();
        inter.close();
        root.close();
    }
    /**
     * Method to create certificate path and to check its validity from a list of certificates.
     * The list of certificates should only contain one root certificate.
     * The root should be at the end of the list.
     * The end-entities should be at the beginning
     * The intermediary should be at the middle
     * */
    private static void checkPathCertificate(FileInputStream[] files) throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<Certificate> mylist = new ArrayList<Certificate>();
        /*X509Certificate root = (X509Certificate) cf.generateCertificate(files[0]);
        X509Certificate inter = (X509Certificate) cf.generateCertificate(files[1]);
        X509Certificate alice = (X509Certificate) cf.generateCertificate(files[2]);*/
        for (FileInputStream f : files) {
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(f);
            mylist.add(certificate);
        }

        CertPath cp = cf.generateCertPath(mylist);

        TrustAnchor anchor = new TrustAnchor((X509Certificate) mylist.get(mylist.size()-1), null);
        PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
        params.setRevocationEnabled(false);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
        System.out.println(result);
    }
    /**
     * Utility method to test if a certificate is self-signed.
     * This is the case if the subject and issuer X500Principals are equal
     * AND the certificate's subject public key can be used to verify the certificate.
     * In case of exception, returns false.
     * */
    public static boolean isSelfSigned(X509Certificate cert) {
        return signedBy(cert, cert);
    }
    public static boolean signedBy(X509Certificate end, X509Certificate ca) {
        if (!ca.getSubjectX500Principal().equals(end.getIssuerX500Principal())) {
            return false;
        }
        try {
            end.verify(ca.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}