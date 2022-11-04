package Ex6;

import org.apache.commons.codec.binary.Base64OutputStream;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;

import static utils.FileUtils.*;
import static utils.FileUtils.writeBase64;

/*
No modo para cifrar, a aplicação também recebe o certificado com a chave pública do destinatário e
produz dois ficheiros, um com o conteúdo original cifrado e outro com a chave simétrica cifrada. Ambos
os ficheiros devem ser codificados em Base64. Valorizam-se soluções que validem o certificado antes de ser
usada a chave pública e que não imponham limites à dimensão do ficheiro a cifrar/decifrar.
*/
public class Encrypter {
    private static final String ENCRYPTEDKEY = "_key.txt";
    private static final String ENCRYPTEDDATA = "_content.txt";
    private static final String ENCRYPTEOUTPUTPACKAGE = "encrypted-output/";

    public static void encrypt(String path, PublicKey publicKey, String secretKeyAlgo, String symmetricAlgo, String asymmetricAlgo) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        System.out.println("Encrypt file");
        //Original content file
        byte[] contentBytes = readFile(path);
        System.out.println("Original content:");
        prettyPrint(contentBytes);

        //Create secret key for symmetric encrypt
        KeyGenerator keyGen = KeyGenerator.getInstance(secretKeyAlgo);
        SecureRandom secRandom = new SecureRandom();
        keyGen.init(secRandom);
        SecretKey secretKey = keyGen.generateKey();
        byte[] secretkeyByte = secretKey.getEncoded();
        System.out.println("Original key:");
        prettyPrint(secretkeyByte);

        //Encrypt content with symmetric algorithm and secret key
        byte[] encDataBytes = Symmetric.encrypt(contentBytes, symmetricAlgo, secretKey);
        System.out.println("Encrypted content:");
        prettyPrint(encDataBytes);

        //Encrypt secret key with asymmetric algorithm with public key
        byte[] encSecretkey = Asymmetric.encrypt(secretkeyByte, asymmetricAlgo, publicKey);
        System.out.println("Encrypted key:");
        prettyPrint(encSecretkey);

        //For encoding in byte stream in Base64 you must use the Apache Commons library Codec.
        Base64OutputStream base64EncSecKey = writeBase64(ENCRYPTEOUTPUTPACKAGE+path.split("\\.")[0].concat(ENCRYPTEDKEY),encSecretkey);
        Base64OutputStream base64EncData = writeBase64(ENCRYPTEOUTPUTPACKAGE+path.split("\\.")[0].concat(ENCRYPTEDDATA),encDataBytes);
        base64EncSecKey.close();
        base64EncData.close();
    }
}
