package Ex5;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static utils.FileUtils.prettyPrint;
import static utils.FileUtils.readFile;

/*
Usando a biblioteca JCA, realize em Java uma aplicação para geração de hashs cripográficos de ficheiros.
A aplicação recebe na linha de comandos i) o nome da função de hash e ii) o ficheiro para o qual se quer
obter o hash. O valor de hash é enviado para o standard output.
Teste a sua aplicação usando certificados (ficheiros .cer) presentes no arquivo certificates-and-keys.zip,
em anexo a este enunciado. Compare o resultado com os valores de hash apresentados pelo visualizador
de certificados do sistema operativo (ou outro da sua confiança).
*/

public class GeneratorHashFile {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        String[] splitcmd = justForTestExample();
        //String[] splitcmd = args;
        Path path = Paths.get(splitcmd[1]);
        byte[] content = readFile(path.toString());
        String hash = splitcmd[0];
        byte[] bytesHashed = null;
        if (hash.equals("SHA-256")){
            bytesHashed = createSHA256Hash(content);
        }
        else if (hash.equals("SHA-1")){
            bytesHashed = createSHA1Hash(content);
        }
        else if (hash.equals("SHA-384")){
            bytesHashed = createSHA384Hash(content);
        }
        else if (hash.equals("SHA-512")){
            bytesHashed = createSHA512Hash(content);
        }
        else if (hash.equals("MD5")){
            bytesHashed = createMD5Hash(content);
        }
        if (bytesHashed!=null)
            prettyPrint(bytesHashed);
    }

    private static String[] justForTestExample() {
        String example = "SHA-256 end-entities/Alice_1.cer";
        return example.split(" ");
    }

    public static byte[] createSHA256Hash(final byte[] msg) throws NoSuchAlgorithmException {
        MessageDigest mdagain = MessageDigest.getInstance("SHA-256"); // for SHA -256
        return mdagain.digest(msg);
    }
    public static byte[] createSHA1Hash(final byte[] msg) throws NoSuchAlgorithmException {
        MessageDigest mdagain = MessageDigest.getInstance("SHA-1"); // for SHA -1
        return mdagain.digest(msg);
    }
    public static byte[] createSHA384Hash(final byte[] msg) throws NoSuchAlgorithmException {
        MessageDigest mdagain = MessageDigest.getInstance("SHA-384"); // for SHA -384
        return mdagain.digest(msg);
    }
    public static byte[] createSHA512Hash(final byte[] msg) throws NoSuchAlgorithmException {
        MessageDigest mdagain = MessageDigest.getInstance("SHA-512"); // for SHA -512
        return mdagain.digest(msg);
    }
    public static byte[] createMD5Hash(final byte[] msg) throws NoSuchAlgorithmException {
        MessageDigest mdagain = MessageDigest.getInstance("MD5"); // for MD5
        return mdagain.digest(msg);
    }
}