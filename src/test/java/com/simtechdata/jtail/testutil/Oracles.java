package com.simtechdata.jtail.testutil;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;

/** Launches the Go interop oracles built by interop/build-oracle.sh; tests skip when they are unavailable. */
public final class Oracles {
    private Oracles() {}

    public static final class Running implements AutoCloseable {
        public final Process process;
        public final BufferedReader out;
        Running(Process p) { this.process = p; this.out = new BufferedReader(new InputStreamReader(p.getInputStream())); }
        public String line() throws IOException { return out.readLine(); }
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
