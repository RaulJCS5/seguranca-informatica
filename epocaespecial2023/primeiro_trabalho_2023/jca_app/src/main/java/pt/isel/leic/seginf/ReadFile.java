package pt.isel.leic.seginf;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

public class ReadFile {
    public static void main(String[] args) {
        String teste = "teste.txt";
        ClassLoader classLoader = ReadFile.class.getClassLoader();
        String filename = classLoader.getResource(teste).getFile();
        ReadFile.readFile(filename);
        byte[] allFileBytes = ReadFile.readFileBytes(filename);
        for (int i = 0; i < allFileBytes.length; i++) {
            System.out.print(allFileBytes[i]+" ");
        }
        System.out.println();
        String text = "Isto é um teste feito por Raul Santos\r\n" +
                "Viva ao Benfica\r\n" +
                "";
        byte[] byteArray = text.getBytes(); // Convert text to byte array
        // Print the byte array (for demonstration purposes)
        for (byte b : byteArray) {
            System.out.print(b + " ");
        }
    }

    public static byte[] readFileBytes(String filename) {
        if (filename == null || filename.isEmpty()) {
            throw new IllegalArgumentException("Filename cannot be null or empty");
        }
        if (filename.length() > 255) {
            throw new IllegalArgumentException("Filename cannot be longer than 255 characters");
        }
        ByteArrayOutputStream out = null;
        InputStream in = null;
        try {
            byte[] buffer = new byte[1024];
            out = new ByteArrayOutputStream();
            in = new FileInputStream(filename);
            int read = 0;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                if (out != null) {
                    out.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
        return out.toByteArray();
    }

    public static void readFile(String filename) {
        try {
            File file = new File(filename);
            Scanner sc = new Scanner(file, "UTF-8");
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                System.out.println(line);
            }
            sc.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }
}
