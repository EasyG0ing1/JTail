package com.simtechdata.jtail.testutil;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Launches the Go interop oracles built by interop/build-oracle.sh; tests skip when they are unavailable. */
public final class Oracles {
    private Oracles() {}

    public static final class Running implements AutoCloseable {
        public final Process process;
        private final BlockingQueue<String> lines = new LinkedBlockingQueue<>();
        private static final String EOF = new String("<eof>");

        Running(Process p) {
            this.process = p;
            Thread t = new Thread(() -> {
                try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                    String l;
                    while ((l = r.readLine()) != null) lines.add(l);
                } catch (IOException ignored) { }
                lines.add(EOF);
            });
            t.setDaemon(true);
            t.start();
        }

        /** Next output line (blocks up to 60 s); null at end of output. */
        public String line() throws IOException { return line(60_000); }

        public String line(long timeoutMs) throws IOException {
            try {
                String l = lines.poll(timeoutMs, TimeUnit.MILLISECONDS);
                if (l == null) throw new IOException("timed out waiting for oracle output");
                return l == EOF ? null : l;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException(e);
            }
        }

        /** Skips lines until one starts with {@code prefix}; returns it. */
        public String expect(String prefix, long timeoutMs) throws IOException {
            long deadline = System.currentTimeMillis() + timeoutMs;
            while (true) {
                long left = deadline - System.currentTimeMillis();
                if (left <= 0) throw new IOException("timed out waiting for '" + prefix + "'");
                String l = line(left);
                if (l == null) throw new IOException("oracle exited while waiting for '" + prefix + "'");
                if (l.startsWith(prefix)) return l;
            }
        }

        public void send(String cmd) throws IOException {
            process.getOutputStream().write((cmd + "\n").getBytes(StandardCharsets.UTF_8));
            process.getOutputStream().flush();
        }

        @Override public void close() { process.destroy(); }
    }

    /** Starts oracle {@code name} (e.g. "go-h2") or skips the calling test if not configured. */
    public static Running start(String name, String... args) throws IOException {
        String dir = System.getProperty("jtail.oracle.dir");
        assumeTrue(dir != null && Files.isExecutable(Path.of(dir, name)), "Go oracle " + name + " not configured");
        String[] cmd = new String[1 + args.length];
        cmd[0] = Path.of(dir, name).toString();
        System.arraycopy(args, 0, cmd, 1, args.length);
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        return new Running(pb.start());
    }
}
