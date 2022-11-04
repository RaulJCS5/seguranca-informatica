package Ex6;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.util.Random;

import static utils.FileUtils.*;

/*
No modo para decifrar, a aplicação recebe também i) ficheiro com conteúdo original cifrado; ii) ficheiro
com chave simétrica cifrada; iii) keystore com a chave privada do destinatário; e produz um novo ficheiro
com o conteúdo original decifrado.
*/
public class Decrypter {
    private static final String DECRYPTEOUTPUTPACKAGE = "decrypted-output/";
    public static void decrypt(String fileContentEncrypted, String fileAsymmetricKeyEncrypted, PrivateKey pvk, String secretKeyAlgo, String symmetricAlgo, String asymmetricAlgo) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        //Decrypt base64 asymmetric key file
        byte[] encSecretKeyByte = readBase64(fileAsymmetricKeyEncrypted);
        System.out.println("Encrypted key:");
        prettyPrint(encSecretKeyByte);

        //Decrypt base64 content file
        byte[] encStrContentByte = readBase64(fileContentEncrypted);
        System.out.println("Encrypted content:");
        prettyPrint(encStrContentByte);

        //Decrypt asymmetric key file with private key to get the original secret key
        byte[] secretKeyBytes = Asymmetric.decrypt(encSecretKeyByte, asymmetricAlgo, pvk);
        System.out.println("Decrypted original key:");
        prettyPrint(secretKeyBytes);
        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, 0, secretKeyBytes.length, secretKeyAlgo);

        //Decrypt content file with secret key to get the original content
        byte[] messageContentByte = Symmetric.decrypt(encStrContentByte, symmetricAlgo, secretKey);
        System.out.println("Decrypted original content:");
        prettyPrint(messageContentByte);
        Random random = new Random();
        int i = random.nextInt();
        writeFile(DECRYPTEOUTPUTPACKAGE+"original"+i+".cer",messageContentByte);
    }
}
