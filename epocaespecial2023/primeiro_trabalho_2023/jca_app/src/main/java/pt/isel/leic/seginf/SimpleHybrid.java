package pt.isel.leic.seginf;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SimpleHybrid {
    public static void main(String[] args) throws CertificateException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, IOException {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Key size in bits
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        // Generate AES key (symmetric key)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // Key size in bits
        SecretKey aesKey = keyGenerator.generateKey();
        // Simulated data to be encrypted
        // Step 1: Encrypt data using AES
        byte[] data = "Hello, World!\n".getBytes();
        System.out.println("Original data: " + Arrays.toString(data));
        Cipher symmetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[symmetricCipher.getBlockSize()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv); // Generate a random initialization vector
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        symmetricCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);
        byte[] encryptedData = symmetricCipher.doFinal(data);
        System.out.println("Symmetric encrypt data" + Arrays.toString(encryptedData));
        // Step 2: Encrypt AES key using RSA
        Cipher asymmetricCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        asymmetricCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = asymmetricCipher.doFinal(aesKey.getEncoded());
        System.out.println("Asymmetric encrypt aesKey" + Arrays.toString(encryptedKey));

        // Simulate sending the encrypted data and encrypted key to the receiver
        // Step 3: Decrypt AES key using RSA
        asymmetricCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = asymmetricCipher.doFinal(encryptedKey);
        SecretKey decryptedAesKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
        System.out.println("Asymmetric decrypt aesKey" + Arrays.toString(decryptedKey));
        // Step 4: Decrypt data using AES
        symmetricCipher.init(Cipher.DECRYPT_MODE, decryptedAesKey, ivParameterSpec);
        byte[] decryptedData = symmetricCipher.doFinal(encryptedData);
        System.out.println("Symmetric decrypt data" + Arrays.toString(decryptedData));

        // Save encrypted data and encrypted key to separate Base64 files
        try (FileOutputStream encryptedDataOutputStream = new FileOutputStream("encrypted_data.txt");
             FileOutputStream encryptedKeyOutputStream = new FileOutputStream("encrypted_key.txt")) {
            encryptedDataOutputStream.write(Base64.getEncoder().encode(encryptedData));
            encryptedKeyOutputStream.write(Base64.getEncoder().encode(encryptedKey));
        }
    }
}
