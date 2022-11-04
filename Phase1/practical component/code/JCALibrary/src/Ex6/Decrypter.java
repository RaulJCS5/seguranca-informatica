package Ex6;

import java.security.*;

/*
No modo para decifrar, a aplicação recebe também i) ficheiro com conteúdo original cifrado; ii) ficheiro
com chave simétrica cifrada; iii) keystore com a chave privada do destinatário; e produz um novo ficheiro
com o conteúdo original decifrado.
*/
public class Decrypter {
    public static void decrypt(String fileContentEncrypted, String fileSymmetricKeyEncrypted, PrivateKey pvk, String secretKeyAlgo, String symmetricAlgo, String asymmetricAlgo){
        System.out.println("Decrypt file");
        //TODO: Not implemented yet
    }
}
