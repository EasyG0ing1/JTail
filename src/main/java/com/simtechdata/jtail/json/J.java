package com.simtechdata.jtail.json;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Null-tolerant typed accessors over the generic JSON object model, mirroring Go's "zero value if absent" decoding. */
public final class J {
    private J() {}

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Map<String, Object> m, String k) { return obj(m.get(k)); }

    public static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof String s ? s : "";
    }

    public static long lng(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof Number n ? n.longValue() : 0L;
    }

    public static int integer(Map<String, Object> m, String k) { return (int) lng(m, k); }

    public static double dbl(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof Number n ? n.doubleValue() : 0.0;
    }

    public static boolean bool(Map<String, Object> m, String k) { return Boolean.TRUE.equals(m.get(k)); }

    /** Tri-state for pointer/opt.Bool fields: null when absent. */
    public static Boolean optBool(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof Boolean b ? b : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> list(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof List ? (List<Object>) v : Collections.emptyList();
    }

    public static List<String> strings(Map<String, Object> m, String k) {
        List<String> out = new ArrayList<>();
        for (Object o : list(m, k)) if (o instanceof String s) out.add(s);
        return out;
    }

    public static List<Long> longs(Map<String, Object> m, String k) {
        List<Long> out = new ArrayList<>();
        for (Object o : list(m, k)) if (o instanceof Number n) out.add(n.longValue());
        return out;
    }

    public static List<Map<String, Object>> objects(Map<String, Object> m, String k) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : list(m, k)) { Map<String, Object> x = obj(o); if (x != null) out.add(x); }
        return out;
    }
}
