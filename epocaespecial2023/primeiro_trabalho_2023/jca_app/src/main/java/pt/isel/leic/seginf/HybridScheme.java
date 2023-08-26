package pt.isel.leic.seginf;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HybridScheme {
    public static void main(String[] args) throws CertificateException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException,
            KeyStoreException, UnrecoverableKeyException {
        if (args.length != 1) {
            System.out.println("Usage: java HybridScheme <-enc|-dec>");
            System.exit(1);
        }
        String cipher = args[0];
        if (cipher.equals("-enc")) {
            // Load the certificate from resource file
            ClassLoader classLoader = HybridScheme.class.getClassLoader();
            InputStream certiInputStream = classLoader.getResourceAsStream("certificates-and-keys/cert-int/CA1-int.cer");
            if (certiInputStream == null) {
                throw new FileNotFoundException("Certificate file not found");
            }
            CertificateFactory certiFactory = CertificateFactory.getInstance("X.509");
            Certificate certi = certiFactory.generateCertificate(certiInputStream);
            // Check if the certificate is valid
            //certi.verify(certi.getPublicKey());
            // Get the public key from the certificate
            PublicKey pubKey = certi.getPublicKey();

            // Generate a symmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            // Simulated data to be encrypted
            byte[] data = "Hello, World!\n".getBytes(); // Read data to be encrypted

            // Encrypt the symmetric key with the public key
            Cipher cipher1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[cipher1.getBlockSize()];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher1.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedData = cipher1.doFinal(data);
            System.out.println("Encrypted data: " + Arrays.toString(encryptedData));

            // Encrypt the symmetric key with the public key
            Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher2.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encryptedKey = cipher2.doFinal(secretKey.getEncoded());
            System.out.println("Encrypted key: " + Arrays.toString(encryptedKey));

            // Save encrypted data and encrypted key to separate Base64 files
            try (FileOutputStream encryptedDataOutputStream = new FileOutputStream("encrypted_data.txt");
                    FileOutputStream encryptedKeyOutputStream = new FileOutputStream("encrypted_key.txt");
                    FileOutputStream encryptedIvOutputStream2 = new FileOutputStream("encrypted_iv.txt");) {
                encryptedDataOutputStream.write(Base64.getEncoder().encode(encryptedData));
                encryptedKeyOutputStream.write(Base64.getEncoder().encode(encryptedKey));
                encryptedIvOutputStream2.write(Base64.getEncoder().encode(iv));
            }
            certiInputStream.close();
        } else if (cipher.equals("-dec")) {
            String encrypted_data = "encrypted_data.txt";
            String encrypted_key = "encrypted_key.txt";
            String encrypted_iv = "encrypted_iv.txt";
            String keystore = "keystore.pfx";

            // Read encrypted data and encrypted key from separate Base64 files
            FileInputStream encryptedDataInputStream = new FileInputStream(encrypted_data); // Read encrypted data
            FileInputStream encryptedKeyInputStream = new FileInputStream(encrypted_key); // Read encrypted key
            FileInputStream encryptedIvInputStream = new FileInputStream(encrypted_iv); // Read encrypted iv

            // Load the private key from PFX (PKCS12) keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream keystoreFileInputStream = new FileInputStream(keystore); // Read keystore
            keyStore.load(keystoreFileInputStream, "changeit".toCharArray());
            Enumeration<String> entries = keyStore.aliases();
            PrivateKey privateKey = null;
            while (entries.hasMoreElements()) {
                String alias = entries.nextElement();
                privateKey = (PrivateKey) keyStore.getKey(alias, "changeit".toCharArray());
            }

            byte[] encryptedData = Base64.getDecoder().decode(encryptedDataInputStream.readAllBytes());
            byte[] encryptedKey = Base64.getDecoder().decode(encryptedKeyInputStream.readAllBytes());
            byte[] iv = Base64.getDecoder().decode(encryptedIvInputStream.readAllBytes());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            Cipher asymmetricCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            asymmetricCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedKey = asymmetricCipher.doFinal(encryptedKey);
            SecretKey decryptedAesKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
            System.out.println("Asymmetric decrypt aesKey" + Arrays.toString(decryptedKey));

            Cipher symmetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            symmetricCipher.init(Cipher.DECRYPT_MODE, decryptedAesKey, ivParameterSpec);
            byte[] decryptedData = symmetricCipher.doFinal(encryptedData);
            System.out.println("Decrypted data" + Arrays.toString(decryptedData));

            // Save decrypted data to file
            try (FileOutputStream decryptedDataOutputStream = new FileOutputStream("decrypted_data.txt");) {
                decryptedDataOutputStream.write(decryptedData);
            }
        } else {
            System.out.println("Usage: java HybridScheme <-enc|-dec>");
            System.exit(1);
        }
    }
}
