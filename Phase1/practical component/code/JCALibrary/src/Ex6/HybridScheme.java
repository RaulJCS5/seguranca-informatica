package Ex6;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Scanner;

/*
Usando a biblioteca JCA, realize em Java uma aplicação para cifrar ficheiros com um esquema híbrido,
ou seja, usando cifra simétrica e assimétrica. O conteúdo do ficheiro é cifrado com uma chave simétrica, a
qual é cifrada com a chave pública do destinatário do ficheiro. A aplicação recebe na linha de comandos
a opção para cifrar (-enc) ou decifrar (-dec) e o ficheiro para cifrar/decifrar.
Para a codificação e descodificação em stream de bytes em Base64 deve usar a biblioteca Apache Commons
Codec [1].
Considere os ficheiros .cer e .pfx em anexo ao enunciado onde estão chaves públicas e privadas necessárias
para testar a aplicação.
*/
public class HybridScheme {
    private static final String PASSWORD = "changeit";
    private static final String SECRETKEYALGO = "AES";
    private static final String SYMMETRICALGO = "AES/ECB/PKCS5Padding";
    private static final String ASYMMETRICALGO = "RSA";

    public static void main(String[] args) throws UnrecoverableKeyException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException, BadPaddingException, SignatureException, IOException, KeyStoreException, InvalidKeyException {
        initalizeApp();
    }
    private static void initalizeApp() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException, InvalidKeyException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        String res;
        String file;
        Cipher cipher = null;
        do {
            Scanner in = new Scanner(System.in);
            System.out.println("-enc or -dec?");
            res = in.nextLine();
            if (cipher == null) {
                cipher = Cipher.getInstance("AES");
            }
            PublicKey pk=null;
            if (res.equalsIgnoreCase("-enc")) {
                System.out.println("Certificate with recipient's public key");
                file = in.nextLine();
                if (!file.contains(".")) {
                    System.out.println("Invalid input");
                }
                else {
                    String fileExtension = file.split("\\.")[1];
                    if (fileExtension.equals("cer")) {
                        pk = getPublicKeyOfcer(file);
                        System.out.println(pk);
                    } else if (fileExtension.equals("pfx")) {
                        //TODO: Not implemented yet
                    } else if (fileExtension.equals("jks")) {
                        //TODO: Not implemented yet
                    } else {
                        System.out.println("Invalid file extension");
                        break;
                    }
                    Encrypter.encrypt(file, pk, SECRETKEYALGO, SYMMETRICALGO, ASYMMETRICALGO);
                }
            } else if (res.equalsIgnoreCase("-dec")) {
                System.out.println("File with original encrypted content");
                String fileContentEncrypted = in.nextLine();
                System.out.println("File with encrypted symmetric key");
                String fileAsymmetricKeyEncrypted = in.nextLine();
                System.out.println("Keystore with recipient's private key");
                String fileKeyStorePrivateKey = in.nextLine();
                PrivateKey pvk=null;
                if (!fileContentEncrypted.contains(".")||!fileAsymmetricKeyEncrypted.contains(".")||!fileKeyStorePrivateKey.contains(".")) {
                    System.out.println("Invalid input");
                }
                else {
                    String fileExtension = fileKeyStorePrivateKey.split("\\.")[1];
                    if (fileExtension.equals("pfx")) {
                        pvk=getPrivateKeyOfpfxWithKS(loadKeyStore(fileKeyStorePrivateKey));
                        System.out.println(pvk);
                    } else {
                        System.out.println("Invalid file extension");
                        break;
                    }
                    Decrypter.decrypt(fileContentEncrypted,fileAsymmetricKeyEncrypted, pvk, SECRETKEYALGO, SYMMETRICALGO, ASYMMETRICALGO);
                }
            }
        } while(!res.equalsIgnoreCase("over"));
    }

    private static PublicKey getPublicKeyOfcer(String file) throws FileNotFoundException, CertificateException {
        FileInputStream inFile = new FileInputStream(String.valueOf(Paths.get(file)));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(inFile);
        return certificate.getPublicKey();
    }

    private static PrivateKey getPrivateKeyOfpfxWithKS(KeyStore loadKeyStore) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        Enumeration<String> entries = loadKeyStore.aliases();
        PrivateKey privateKey = null;
        while (entries.hasMoreElements()) {
            String alias = entries.nextElement();
            //X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            //PublicKey publicKey = cert.getPublicKey();
            privateKey = (PrivateKey) loadKeyStore.getKey(alias, PASSWORD.toCharArray());
        }
        return privateKey;
    }

    private static KeyStore loadKeyStore(String fileKeyStorePrivateKey) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        char[] keyStorePassword = PASSWORD.toCharArray();
        KeyStore keyStore =  KeyStore.getInstance("PKCS12");
        FileInputStream f = new FileInputStream(fileKeyStorePrivateKey);
        keyStore.load(f, keyStorePassword);
        return keyStore;
    }
}
