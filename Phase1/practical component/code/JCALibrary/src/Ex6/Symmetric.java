package Ex6;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Symmetric {
    public static byte[] encrypt(byte[] contentBytes, String symmetricAlgo, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(symmetricAlgo);//"AES/ECB/PKCS5Padding"
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(contentBytes);
    }
    public static byte[] decrypt(byte[] encStrContentByte, String symmetricAlgo, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(symmetricAlgo);//"AES/ECB/PKCS5Padding"
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encStrContentByte);
    }
}
