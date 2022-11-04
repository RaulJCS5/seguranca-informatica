package Ex6;

import java.security.*;

/*
No modo para cifrar, a aplicação também recebe o certificado com a chave pública do destinatário e
produz dois ficheiros, um com o conteúdo original cifrado e outro com a chave simétrica cifrada. Ambos
os ficheiros devem ser codificados em Base64. Valorizam-se soluções que validem o certificado antes de ser
usada a chave pública e que não imponham limites à dimensão do ficheiro a cifrar/decifrar.
*/
public class Encrypter {
    public static void encrypt(String path, PublicKey publicKey, String secretKeyAlgo, String symmetricAlgo, String asymmetricAlgo) {
        System.out.println("Encrypt file");
        //TODO: Not implemented yet
    }
}
