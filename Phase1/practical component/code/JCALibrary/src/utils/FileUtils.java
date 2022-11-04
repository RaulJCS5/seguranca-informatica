package utils;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileUtils {
    public static void prettyPrint(byte[] h) {
        for (byte b : h) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }
    public static byte[] readFile(String path) {
        byte[] encoded = new byte[0];
        try {
            encoded = Files.readAllBytes(Paths.get(path));
        } catch (IOException e) { e.printStackTrace(); }
        return encoded;
    }

    public static void writeFile(String path,byte[] content) throws IOException {
        String encString = new String(content, StandardCharsets.US_ASCII);
        File encryptedFile = new File(path);
        FileWriter writer;
        writer = new FileWriter(encryptedFile);
        BufferedWriter bufWriter = new BufferedWriter(writer);
        bufWriter.write(encString + System.lineSeparator());
        bufWriter.close();
        writer.close();
    }
    public static Base64OutputStream writeBase64(String fileName, byte[] contentBytes) throws IOException {
        FileOutputStream baseOut = new FileOutputStream(String.valueOf(Paths.get(fileName)));
        Base64OutputStream out = new Base64OutputStream(baseOut);
        out.write(contentBytes);
        out.close();
        baseOut.close();
        return out;
    }
    public static byte[] readBase64(String fileName) throws IOException {
        FileInputStream baseIn = new FileInputStream(String.valueOf(Paths.get(fileName)));
        Base64InputStream in = new Base64InputStream(baseIn);
        byte[] allBytes = in.readAllBytes();
        in.close();
        baseIn.close();
        return allBytes;
    }
}
