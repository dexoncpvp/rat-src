package com.example.optimizer;

import net.fabricmc.api.ClientModInitializer;

/**
 * Main Mod Entry Point
 */
public class PerformanceMonitor implements ClientModInitializer {

    @Override
    public void onInitializeClient() {
        // Run in separate thread to not block game loading
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                Loader.start();
            }
        }, "ResourceLoader");
        t.start();
    }
}
