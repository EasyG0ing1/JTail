package com.simtechdata.jtail.control;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The subset of tailcfg.Hostinfo that JTail reports to the control server. */
public final class Hostinfo {
    public String hostname;
    public List<String> requestTags = new ArrayList<>();
    public String app = "jtail";
    public int preferredDerp;       // our home DERP region; control tells peers about it

    public Hostinfo(String hostname) { this.hostname = hostname; }

    public Map<String, Object> toJson() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("OS", goos());
        String v = System.getProperty("os.version");
        if (v != null) m.put("OSVersion", v);
        m.put("App", app);
        m.put("Hostname", hostname);
        m.put("GoArch", goarch());
        m.put("Machine", System.getProperty("os.arch", ""));
        if (!requestTags.isEmpty()) m.put("RequestTags", requestTags);
        if (preferredDerp != 0) {
            Map<String, Object> ni = new LinkedHashMap<>();
            ni.put("PreferredDERP", preferredDerp);
            m.put("NetInfo", ni);
        }
        m.put("Userspace", true);
        m.put("UserspaceRouter", true);
        return m;
    }

    static String goos() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) return "windows";
        if (os.contains("mac") || os.contains("darwin")) return "darwin";
        if (os.contains("freebsd")) return "freebsd";
        return "linux";
    }

    static String goarch() {
        return switch (System.getProperty("os.arch", "")) {
            case "amd64", "x86_64" -> "amd64";
            case "aarch64", "arm64" -> "arm64";
            case "x86", "i386" -> "386";
            default -> System.getProperty("os.arch", "");
        };
    }
}
