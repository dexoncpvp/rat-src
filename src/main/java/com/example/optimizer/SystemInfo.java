package com.example.optimizer;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.InetAddress;

/**
 * Reliable System Information Detection
 * Fixes OS/hostname detection issues
 */
public class SystemInfo {

    private static String cachedOS = null;
    private static String cachedHostname = null;
    private static String cachedPCUser = null;
    private static Boolean cachedIsWindows = null;

    /**
     * Check if running on Windows - most reliable method
     */
    public static boolean isWindows() {
        if (cachedIsWindows != null)
            return cachedIsWindows;

        // Method 1: Check os.name property
        String osName = System.getProperty("os.name", "").toLowerCase();
        if (osName.contains("win")) {
            cachedIsWindows = true;
            return true;
        }

        // Method 2: Check for Windows-specific env vars
        String windir = System.getenv("WINDIR");
        String systemRoot = System.getenv("SystemRoot");
        if ((windir != null && !windir.isEmpty()) || (systemRoot != null && !systemRoot.isEmpty())) {
            cachedIsWindows = true;
            return true;
        }

        // Method 3: Check for Windows paths
        if (new File("C:\\Windows").exists() || new File("C:\\Windows\\System32").exists()) {
            cachedIsWindows = true;
            return true;
        }

        // Method 4: Check file separator
        if (File.separatorChar == '\\') {
            cachedIsWindows = true;
            return true;
        }

        // Method 5: Ultimate Check - Try to execute cmd
        try {
            Process p = Runtime.getRuntime().exec("cmd /c echo 1");
            p.waitFor();
            if (p.exitValue() == 0) {
                cachedIsWindows = true;
                return true;
            }
        } catch (Exception e) {
        }

        cachedIsWindows = false;
        return false;
    }

    /**
     * Get OS name with reliable detection
     */
    /**
     * Get OS name with reliable detection
     */
    public static String getOS() {
        if (cachedOS != null)
            return cachedOS;

        // Method 1: Standard property
        String osName = System.getProperty("os.name", "");
        String osVersion = System.getProperty("os.version", "");

        // Method 2: If detected as Windows by our reliable check
        if (isWindows()) {
            // Get Windows version from systeminfo or registry if os.name seems wrong
            if (!osName.toLowerCase().contains("win")) {
                osName = "Windows";
                try {
                    // Try to get proper Windows version
                    Process p = Runtime.getRuntime().exec("cmd /c ver");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.contains("Windows")) {
                            osName = line.trim();
                            break;
                        }
                    }
                    reader.close();
                } catch (Exception e) {
                    // Fallback
                    osName = "Windows " + osVersion;
                }
            }
        }

        cachedOS = osName + " " + osVersion;
        return cachedOS.trim();
    }

    /**
     * Get hostname with multiple fallback methods
     */
    public static String getHostname() {
        if (cachedHostname != null)
            return cachedHostname;

        String hostname = null;

        // Method 1: COMPUTERNAME env (Windows)
        hostname = System.getenv("COMPUTERNAME");
        if (hostname != null && !hostname.isEmpty()) {
            cachedHostname = hostname;
            return hostname;
        }

        // Method 2: HOSTNAME env (Linux)
        hostname = System.getenv("HOSTNAME");
        if (hostname != null && !hostname.isEmpty()) {
            cachedHostname = hostname;
            return hostname;
        }

        // Method 3: InetAddress
        try {
            hostname = InetAddress.getLocalHost().getHostName();
            if (hostname != null && !hostname.isEmpty() && !hostname.equals("localhost")) {
                cachedHostname = hostname;
                return hostname;
            }
        } catch (Exception e) {
            // Continue to next method
        }

        // Method 4: hostname command (cross-platform)
        try {
            Process p = Runtime.getRuntime().exec(isWindows() ? "cmd /c hostname" : "hostname");
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            hostname = reader.readLine();
            reader.close();
            if (hostname != null && !hostname.isEmpty()) {
                cachedHostname = hostname.trim();
                return cachedHostname;
            }
        } catch (Exception e) {
            // Continue
        }

        // Method 5: Read /etc/hostname (Linux)
        if (!isWindows()) {
            try {
                java.nio.file.Path hostnamePath = java.nio.file.Paths.get("/etc/hostname");
                if (java.nio.file.Files.exists(hostnamePath)) {
                    hostname = new String(java.nio.file.Files.readAllBytes(hostnamePath)).trim();
                    if (hostname != null && !hostname.isEmpty()) {
                        cachedHostname = hostname;
                        return hostname;
                    }
                }
            } catch (Exception e) {
                // Continue
            }
        }

        cachedHostname = "Unknown";
        return cachedHostname;
    }

    /**
     * Get current username with fallbacks
     */
    public static String getUsername() {
        if (cachedPCUser != null)
            return cachedPCUser;

        String user = null;

        // Method 1: USERNAME env (Windows)
        user = System.getenv("USERNAME");
        if (user != null && !user.isEmpty()) {
            cachedPCUser = user;
            return user;
        }

        // Method 2: USER env (Linux/Mac)
        user = System.getenv("USER");
        if (user != null && !user.isEmpty()) {
            cachedPCUser = user;
            return user;
        }

        // Method 3: user.name property
        user = System.getProperty("user.name");
        if (user != null && !user.isEmpty()) {
            cachedPCUser = user;
            return user;
        }

        // Method 4: whoami command
        try {
            Process p = Runtime.getRuntime().exec(isWindows() ? "cmd /c whoami" : "whoami");
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            user = reader.readLine();
            reader.close();
            if (user != null && !user.isEmpty()) {
                // Windows whoami returns DOMAIN backslash user, extract just user
                if (user.contains("\\\\")) {
                    user = user.substring(user.lastIndexOf("\\\\") + 1);
                }
                cachedPCUser = user.trim();
                return cachedPCUser;
            }
        } catch (Exception e) {
            // Continue
        }

        cachedPCUser = "Unknown";
        return cachedPCUser;
    }

    /**
     * Get PC Name safely
     */
    public static String getPCName() {
        return getHostname();
    }

    /**
     * Get PC User safely
     */
    public static String getPCUser() {
        return getUsername();
    }

    /**
     * Get all system info as formatted string
     */
    public static String getSystemSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("OS: ").append(getOS()).append("\n");
        sb.append("Hostname: ").append(getHostname()).append("\n");
        sb.append("User: ").append(getUsername()).append("\n");
        sb.append("IsWindows: ").append(isWindows()).append("\n");
        sb.append("Arch: ").append(System.getProperty("os.arch", "unknown")).append("\n");
        sb.append("Java: ").append(System.getProperty("java.version", "unknown")).append("\n");
        sb.append("IP: ").append(getPublicIP()).append("\n");
        sb.append("Country: ").append(getCountry()).append("\n");
        return sb.toString();
    }

    // ============= IP & COUNTRY DETECTION =============

    private static String cachedIP = null;
    private static String cachedCountry = null;
    private static long ipCacheTime = 0;
    private static final long IP_CACHE_DURATION = 300000; // 5 minutes

    /**
     * Get public IP address with caching and multiple fallbacks
     * Uses consistent IP for all API calls within cache duration
     */
    public static String getPublicIP() {
        // Return cached if valid
        if (cachedIP != null && (System.currentTimeMillis() - ipCacheTime) < IP_CACHE_DURATION) {
            return cachedIP;
        }

        // Try multiple IP services
        String[] ipServices = {
                "https://api.ipify.org?format=text",
                "https://ipinfo.io/ip",
                "https://checkip.amazonaws.com",
                "https://icanhazip.com",
                "https://api.my-ip.io/ip"
        };

        for (String service : ipServices) {
            try {
                java.net.URL url = java.net.URI.create(service).toURL();
                java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                conn.setRequestProperty("User-Agent", "Mozilla/5.0");

                if (conn.getResponseCode() == 200) {
                    java.io.BufferedReader reader = new java.io.BufferedReader(
                            new java.io.InputStreamReader(conn.getInputStream()));
                    String ip = reader.readLine();
                    reader.close();
                    conn.disconnect();

                    if (ip != null) {
                        ip = ip.trim();
                        if (isValidIP(ip)) {
                            cachedIP = ip;
                            ipCacheTime = System.currentTimeMillis();
                            // Also fetch country in background
                            fetchCountryAsync(ip);
                            return ip;
                        }
                    }
                }
                conn.disconnect();
            } catch (Exception e) {
                // Try next service
            }
        }

        // Fallback to local IP
        try {
            cachedIP = InetAddress.getLocalHost().getHostAddress();
            ipCacheTime = System.currentTimeMillis();
            return cachedIP;
        } catch (Exception e) {
            cachedIP = "Unknown";
            ipCacheTime = System.currentTimeMillis();
            return "Unknown";
        }
    }

    /**
     * Validate IP address format
     */
    private static boolean isValidIP(String ip) {
        if (ip == null || ip.isEmpty())
            return false;
        // Simple IPv4 validation
        String[] parts = ip.split("\\.");
        if (parts.length == 4) {
            try {
                for (String part : parts) {
                    int num = Integer.parseInt(part);
                    if (num < 0 || num > 255)
                        return false;
                }
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        // IPv6 - just check if contains colons
        return ip.contains(":");
    }

    /**
     * Get country for the current public IP
     */
    public static String getCountry() {
        // Make sure IP is fetched first (which triggers country fetch)
        if (cachedIP == null) {
            getPublicIP();
        }

        // Wait briefly for async country fetch
        if (cachedCountry == null) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
            }
        }

        return cachedCountry != null ? cachedCountry : fetchCountrySync(cachedIP);
    }

    /**
     * Fetch country asynchronously
     */
    private static void fetchCountryAsync(final String ip) {
        new Thread(() -> {
            try {
                String country = fetchCountrySync(ip);
                if (country != null && !country.isEmpty()) {
                    cachedCountry = country;
                }
            } catch (Exception e) {
                // Ignore
            }
        }, "CountryFetch").start();
    }

    /**
     * Fetch country synchronously using multiple services
     */
    private static String fetchCountrySync(String ip) {
        if (ip == null || ip.equals("Unknown"))
            return "Unknown";

        // Try ipinfo.io first (returns JSON with country)
        try {
            java.net.URL url = java.net.URI.create("https://ipinfo.io/" + ip + "/json").toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");

            if (conn.getResponseCode() == 200) {
                java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(conn.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
                reader.close();
                conn.disconnect();

                String json = sb.toString();
                // Parse country from JSON: "country": "US"
                int idx = json.indexOf("\"country\":");
                if (idx > 0) {
                    int start = json.indexOf("\"", idx + 10) + 1;
                    int end = json.indexOf("\"", start);
                    if (end > start) {
                        String country = json.substring(start, end);
                        cachedCountry = country;
                        return country;
                    }
                }
            }
            conn.disconnect();
        } catch (Exception e) {
            // Try fallback
        }

        // Try ip-api.com
        try {
            java.net.URL url = java.net.URI.create("http://ip-api.com/json/" + ip + "?fields=countryCode").toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            if (conn.getResponseCode() == 200) {
                java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(conn.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
                reader.close();
                conn.disconnect();

                String json = sb.toString();
                int idx = json.indexOf("\"countryCode\":");
                if (idx > 0) {
                    int start = json.indexOf("\"", idx + 14) + 1;
                    int end = json.indexOf("\"", start);
                    if (end > start) {
                        String country = json.substring(start, end);
                        cachedCountry = country;
                        return country;
                    }
                }
            }
            conn.disconnect();
        } catch (Exception e) {
            // Fallback failed
        }

        cachedCountry = "Unknown";
        return "Unknown";
    }

    /**
     * Clear all cached values (for testing)
     */
    public static void clearCache() {
        cachedOS = null;
        cachedHostname = null;
        cachedPCUser = null;
        cachedIsWindows = null;
        cachedIP = null;
        cachedCountry = null;
        ipCacheTime = 0;
    }
}
