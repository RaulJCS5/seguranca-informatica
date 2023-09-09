package pt.isel.leic.seginf;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.net.URL;

public class HashFunctions {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java HashFunctions <filename> <algorithm>");
            System.exit(1);
        }
        String filename = args[0];
        String algorithm = args[1];
        String hash = computeHashFile(filename, algorithm);
        System.out.println("Hash: " + hash + " (" + algorithm + ")");
        
        /*
        // For testing purposes
        String inputData = "Hello, world!";
        String inputFile = "C:\Users\raulj\Desktop\epoca_especial_eemestreverao2023\SegInf\seginf-inv2223-private\epocaespecial2023\primeiro_trabalho_2023\jca_app\src\main\resources\teste.txt";

        System.out.println("Original Data: " + inputData);
        System.out.println("MD5 Hash: " + computeHashString(inputData, "MD5"));
        System.out.println("MD5 Hash: " + computeHashFile(inputFile, "MD5"));
        System.out.println("SHA-1 Hash: " + computeHashString(inputData, "SHA-1"));
        System.out.println("SHA-1 Hash: " + computeHashFile(inputFile, "SHA-1"));
        System.out.println("SHA-256 Hash: " + computeHashString(inputData, "SHA-256"));
        System.out.println("SHA-256 Hash: " + computeHashFile(inputFile, "SHA-256"));
        System.out.println("SHA-512 Hash: " + computeHashString(inputData, "SHA-512"));
        System.out.println("SHA-512 Hash: " + computeHashFile(inputFile, "SHA-512"));*/
        /*
        openssl dgst -md5 <filename>
        openssl dgst -sha1 <filename>
        openssl dgst -sha256 <filename>
        openssl dgst -sha512 <filename>
        */
    }

    private static String computeHashFile(String inputFile, String algorithm) {
        try(InputStream inputStream = new FileInputStream(inputFile)){
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] buffer = new byte[1024];
            int bytesRead;
            while((bytesRead = inputStream.read(buffer)) != -1){
                digest.update(buffer, 0, bytesRead);
            }

            byte[] hash = digest.digest();

            StringBuilder hexString = new StringBuilder();
            for(byte b : hash){
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();

        }catch( NoSuchAlgorithmException | IOException ex){
            throw new RuntimeException(ex);
        }
    }

    private static String computeHashString(String inputData, String algorithm) {
        try{
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hash = digest.digest(inputData.getBytes("UTF-8"));

            StringBuilder hexString = new StringBuilder();
            for(byte b : hash){
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        }catch(UnsupportedEncodingException | NoSuchAlgorithmException ex){
            throw new RuntimeException(ex);
        }
    }
}
