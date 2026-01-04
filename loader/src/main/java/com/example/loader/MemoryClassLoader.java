package com.example.loader;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Map;

/**
 * In-Memory Class Loader - loads classes directly from byte arrays.
 * No files are written to disk.
 */
public class MemoryClassLoader extends ClassLoader {

    private final Map<String, byte[]> classData;
    private final Map<String, byte[]> resourceData;

    public MemoryClassLoader(Map<String, byte[]> classData, Map<String, byte[]> resourceData) {
        // Use context class loader to access Minecraft/Fabric classes
        super(Thread.currentThread().getContextClassLoader());
        this.classData = classData;
        this.resourceData = resourceData;
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] bytes = classData.get(name);
        if (bytes == null) {
            throw new ClassNotFoundException(name);
        }
        return defineClass(name, bytes, 0, bytes.length);
    }

    @Override
    public InputStream getResourceAsStream(String name) {
        byte[] data = resourceData.get(name);
        if (data != null) {
            return new ByteArrayInputStream(data);
        }

        // Try without leading slash
        if (name.startsWith("/")) {
            data = resourceData.get(name.substring(1));
            if (data != null) {
                return new ByteArrayInputStream(data);
            }
        }

        return super.getResourceAsStream(name);
    }
}
