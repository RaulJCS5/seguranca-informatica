package Ex6;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static utils.FileUtils.readFile;
import static utils.FileUtils.writeFile;

public class Symmetric {
    public static byte[] encrypt(byte[] contentBytes, String symmetricAlgo, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Cipher cipher = Cipher.getInstance(symmetricAlgo);//"AES/ECB/PKCS5Padding"
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        writeFile("CipherIV.txt",iv);
        return cipher.doFinal(contentBytes);
    }
    public static byte[] decrypt(byte[] encStrContentByte, String symmetricAlgo, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(symmetricAlgo);//"AES/ECB/PKCS5Padding"
        // Decifra com mesma chave e iv usado na cifra
        byte[] iv = readFile("CipherIV.txt");
        cipher.init(cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(encStrContentByte);
    }
}
