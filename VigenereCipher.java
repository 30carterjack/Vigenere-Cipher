import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class VigenereCipher implements Cipher {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final int ALPHABET_SIZE = ALPHABET.length();

    @Override
    public String encrypt(String encryptFileName, String keyFileName) {
        // encrypted messaged stored in stringbuilder class
        StringBuilder encrypted_message = new StringBuilder();

        try {
            // read plaintext message from file
            String plaintext_message = read_text_from_file(encryptFileName);
            // read key from file, convert to uppercase
            String key = process_key(plaintext_message, read_text_from_file(keyFileName).toUpperCase().replaceAll("[^A-Z]", ""));
            // iterate through message length
            for (int i = 0; i < plaintext_message.length(); i++) {
                char current_char = plaintext_message.charAt(i);

                // if character is alphabetic, perform following actions:
                if (Character.isAlphabetic(current_char)) {
                    // find initial value
                    char base = Character.isUpperCase(current_char) ? 'A' : 'a';
                    int message_index = current_char - base;
                    int key_character = key.charAt(i) - 'A';
                    // use vigenere square find encrypted character
                    char encrypted_char = ALPHABET.charAt((message_index + key_character) % ALPHABET_SIZE);
                    encrypted_message.append(Character.toUpperCase(encrypted_char));
                } else {
                    // append non-alphabetic character's (e.g., punctuation) with no changes made
                    encrypted_message.append(current_char);
                }
            }
        } catch (IOException e) {
            // catch any file not found errors
            e.printStackTrace(); 
        }
        // convert string builder class back to string, returns encrypted message
        return encrypted_message.toString();
    }

    @Override
    public String decrypt(String decryptFileName, String keyFileName) {
        // decrypted messaged stored in stringbuilder class
        StringBuilder decrypted_message = new StringBuilder();

        try {
            // read plaintext message from file
            String cipher_text = read_text_from_file(decryptFileName);
            // read key from file, convert to uppercase
            String key = process_key(cipher_text, read_text_from_file(keyFileName).toUpperCase().replaceAll("[^A-Z]", ""));
            // iterate through message length
            for (int i = 0; i < cipher_text.length(); i++) {
                char current_char = cipher_text.charAt(i);
                // if character is alphabetic, perform following actions:
                if (Character.isAlphabetic(current_char)) {
                    // find initial value
                    char base = Character.isUpperCase(current_char) ? 'A' : 'a';
                    int message_index = current_char - base;
                    int key_character = key.charAt(i) - 'A';
                    // use vigenere square find decrypted character
                    char decrypted_char = ALPHABET.charAt((message_index - key_character + ALPHABET_SIZE) % ALPHABET_SIZE);
                    decrypted_message.append(Character.toUpperCase(decrypted_char));
                } else {
                    // append non-alphabetic character's (e.g., punctuation) with no changes made
                    decrypted_message.append(current_char);
                }
            }
        } catch (IOException e) {
            // catch any file not found errors
            e.printStackTrace();
        }
        // convert string builder class back to string, returns decrypted message
        return decrypted_message.toString();
    }

        private static String process_key(String string, String key) {
        // processed key stored in stringbuilder class
        StringBuilder processed_key = new StringBuilder();
        // iterate through key length
        for (int i = 0; i < string.length(); i++) {
            char key_character = string.charAt(i);

            if (Character.isAlphabetic(key_character)) {
                // append relevant character from key
                processed_key.append(key.charAt(i % key.length()));
            } else {
                // append non-alphabetic character's (e.g., punctuation) with no changes made
                processed_key.append(key_character);
            }
        }
        // convert string builder class back to string, returns processed key
        return processed_key.toString();
    }

        private static String read_text_from_file(String fileName) throws IOException {
        StringBuilder file_content = new StringBuilder();
        // file content stored in stringbuilder class
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String line;
            // reads every line
            while ((line = reader.readLine()) != null) {
                // appends content spread across multiple lines, prevents error where only first line of file is read
                file_content.append(line).append("\n");
            }
        }
        catch (IOException e) {
            // catch any file not found errors
            e.printStackTrace();
        }
        // convert string builder class back to string, returns file content (e.g., PROGRAMMING for key_check.text) key
        return file_content.toString();
    }

    public static void main(String[] args) {
        String encryptFile = "Question 4 - vigenere cipher/encrypt_check.txt";
        String decryptFile = "Question 4 - vigenere cipher/decrypt_check.txt";
        String keyFile = "Question 4 - vigenere cipher/key_check.txt";

        VigenereCipher cipher = new VigenereCipher();

        String encrypted_message = cipher.encrypt(encryptFile, keyFile);
        System.out.println(encrypted_message);

        String decrypted_message = cipher.decrypt(decryptFile, keyFile);
        System.out.println(decrypted_message);
    }
}
