import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import java.util.Base64;

public class Main {
    private static final int ITERATIONS = 10000;
    private static final int KEY_LENGTH = 256;
    private static final byte[] SALT = "MySaltValue".getBytes(); // 定義固定的 salt 值
    private static final String PASSWORD = "ITRIPASSWORD"; // 定義要加密的明文密碼
    private static final byte[] KEY; // 透過SHA256定義加密金鑰

    static {
        // 產生加密金鑰
        try {
            PBEKeySpec spec = new PBEKeySpec(PASSWORD.toCharArray(), SALT, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KEY = keyFactory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to generate secret key", e);
        }
    }

    public static String encrypt(String plainText) {
        try {
            // 產生加密器
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
            javax.crypto.spec.IvParameterSpec ivParams = new javax.crypto.spec.IvParameterSpec(new byte[16]);
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(KEY, "AES");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec, ivParams);

            // 加密字串
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));

            // 回傳加密後的字串
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt string", e);
        }
    }

    public static String decrypt(String encryptedText) {
        try {
            // 產生解密器
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
            javax.crypto.spec.IvParameterSpec ivParams = new javax.crypto.spec.IvParameterSpec(new byte[16]);
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(KEY, "AES");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, ivParams);

            // 解密字串
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

            // 回傳解密後的字串
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt string", e);
        }
    }

    public static void main(String[] args) {
        //String plainText = "Hello ITRI!";
        Scanner scanner = new Scanner(System.in);
        System.out.println("Please enter ENC(encryption) or DEC(decryption) MODE：");
        String mode = scanner.next();
        if (mode.equals("ENC")) {
            System.out.println("Please enter the encrypt Text：");
            String plainText = scanner.next();
            String encryptedText = encrypt(plainText);
            System.out.println("Encrypted: " + encryptedText);
        } else if (mode.equals("DEC")) {
            System.out.println("Please enter the encrypted Text：");
            String encryptedText = scanner.next();
            String decryptedText = decrypt(encryptedText);
            System.out.println("Decrypted: " + decryptedText);
        }

    }
}