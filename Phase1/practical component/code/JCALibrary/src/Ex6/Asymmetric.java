package Ex6;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class Asymmetric {
    public static byte[] encrypt(byte[] secretkeyByte, String asymmetricAlgo, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(asymmetricAlgo);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretkeyByte);
    }
}
