package Ex6;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;

/*
Usando a biblioteca JCA, realize em Java uma aplicação para cifrar ficheiros com um esquema híbrido,
ou seja, usando cifra simétrica e assimétrica. O conteúdo do ficheiro é cifrado com uma chave simétrica, a
qual é cifrada com a chave pública do destinatário do ficheiro. A aplicação recebe na linha de comandos
a opção para cifrar (-enc) ou decifrar (-dec) e o ficheiro para cifrar/decifrar.
No modo para cifrar, a aplicação também recebe o certificado com a chave pública do destinatário e
produz dois ficheiros, um com o conteúdo original cifrado e outro com a chave simétrica cifrada. Ambos
os ficheiros devem ser codificados em Base64. Valorizam-se soluções que validem o certificado antes de ser
usada a chave pública e que não imponham limites à dimensão do ficheiro a cifrar/decifrar.
No modo para decifrar, a aplicação recebe também i) ficheiro com conteúdo original cifrado; ii) ficheiro
com chave simétrica cifrada; iii) keystore com a chave privada do destinatário; e produz um novo ficheiro
com o conteúdo original decifrado.
Para a codificação e descodificação em stream de bytes em Base64 deve usar a biblioteca Apache Commons
Codec [1].
Considere os ficheiros .cer e .pfx em anexo ao enunciado onde estão chaves públicas e privadas necessárias
para testar a aplicação.
*/
public class HybridScheme {
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
            if (res.equalsIgnoreCase("-enc")) {
                System.out.println("Certificate with recipient's public key");
                file = in.nextLine();
                if (!file.contains(".")) {
                    System.out.println("Invalid input");
                }
                else {
                    String fileExtension = file.split("\\.")[1];
                    if (fileExtension.equals("cer")) {
                        //TODO: Not implemented yet
                    } else if (fileExtension.equals("pfx")) {
                        //TODO: Not implemented yet
                    } else if (fileExtension.equals("jks")) {
                        //TODO: Not implemented yet
                    } else {
                        System.out.println("Invalid file extension");
                        break;
                    }
                    //TODO: Do encrypt
                }
            } else if (res.equalsIgnoreCase("-dec")) {
                System.out.println("File with original encrypted content");
                String fileContentEncrypted = in.nextLine();
                System.out.println("File with encrypted symmetric key");
                String fileSymmetricKeyEncrypted = in.nextLine();
                System.out.println("Keystore with recipient's private key");
                String fileKeyStorePrivateKey = in.nextLine();
                if (!fileContentEncrypted.contains(".")||!fileSymmetricKeyEncrypted.contains(".")||!fileKeyStorePrivateKey.contains(".")) {
                    System.out.println("Invalid input");
                }
                else {
                    String fileExtension = fileKeyStorePrivateKey.split("\\.")[1];
                    if (fileExtension.equals("pfx")) {
                        //TODO: Not implemented yet
                    } else {
                        System.out.println("Invalid file extension");
                        break;
                    }
                    //TODO: Do decrypt
                }
            }
        } while(!res.equalsIgnoreCase("over"));
    }
}
