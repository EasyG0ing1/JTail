package com.simtechdata.jtail.json;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, dependency-free JSON parser and writer.
 * Values map to: {@code Map<String,Object>} (insertion-ordered), {@code List<Object>}, {@code String},
 * {@code Long} (integers that fit) or {@code Double}, {@code Boolean}, and {@code null}.
 */
public final class Json {
    private Json() {}

    public static Object parse(String s) throws IOException {
        Parser p = new Parser(s);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != s.length()) throw p.err("trailing data");
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String s) throws IOException {
        Object v = parse(s);
        if (!(v instanceof Map)) throw new IOException("expected JSON object");
        return (Map<String, Object>) v;
    }

    public static String write(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof String s) quote(sb, s);
        else if (v instanceof Boolean || v instanceof Long || v instanceof Integer || v instanceof Short || v instanceof Byte) sb.append(v);
        else if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("non-finite number");
            if (d == Math.rint(d) && Math.abs(d) < 1e15) sb.append((long) d); else sb.append(d);
        } else if (v instanceof Map<?, ?> m) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) m).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                quote(sb, e.getKey());
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof Iterable<?> it) {
            sb.append('[');
            boolean first = true;
            for (Object o : it) { if (!first) sb.append(','); first = false; write(sb, o); }
            sb.append(']');
        } else if (v instanceof byte[] b) {
            quote(sb, java.util.Base64.getEncoder().encodeToString(b)); // Go encodes []byte as base64
        } else throw new IllegalArgumentException("unsupported JSON type " + v.getClass());
    }

    private static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c)); else sb.append(c);
                }
            }
        }
        sb.append('"');
    }

    private static final class Parser {
        final String s;
        int i;
        int depth;

        Parser(String s) { this.s = s; }

        IOException err(String m) { return new IOException("json: " + m + " at offset " + i); }

        void ws() { while (i < s.length() && " \t\r\n".indexOf(s.charAt(i)) >= 0) i++; }

        Object value() throws IOException {
            if (i >= s.length()) throw err("unexpected end");
            char c = s.charAt(i);
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': lit("true"); return Boolean.TRUE;
                case 'f': lit("false"); return Boolean.FALSE;
                case 'n': lit("null"); return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) return number();
                    throw err("unexpected character '" + c + "'");
            }
        }

        void lit(String w) throws IOException {
            if (!s.startsWith(w, i)) throw err("bad literal");
            i += w.length();
        }

        Object number() throws IOException {
            int st = i;
            if (s.charAt(i) == '-') i++;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            boolean isInt = true;
            if (i < s.length() && s.charAt(i) == '.') { isInt = false; i++; while (i < s.length() && Character.isDigit(s.charAt(i))) i++; }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                isInt = false; i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            }
            String t = s.substring(st, i);
            try {
                if (isInt) {
                    try { return Long.parseLong(t); } catch (NumberFormatException e) { return Double.parseDouble(t); }
                }
                return Double.parseDouble(t);
            } catch (NumberFormatException e) { throw err("bad number " + t); }
        }

        String string() throws IOException {
            i++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (i >= s.length()) throw err("unterminated string");
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (i >= s.length()) throw err("bad escape");
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"', '\\', '/' -> sb.append(e);
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'u' -> {
                            if (i + 4 > s.length()) throw err("bad unicode escape");
                            try { sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); }
                            catch (NumberFormatException ex) { throw err("bad unicode escape"); }
                            i += 4;
                        }
                        default -> throw err("bad escape \\" + e);
                    }
                } else if (c < 0x20) {
                    throw err("control character in string");
                } else sb.append(c);
            }
        }

        List<Object> array() throws IOException {
            if (++depth > 512) throw err("nesting too deep");
            i++;
            List<Object> out = new ArrayList<>();
            ws();
            if (i < s.length() && s.charAt(i) == ']') { i++; depth--; return out; }
            while (true) {
                ws();
                out.add(value());
                ws();
                if (i >= s.length()) throw err("unterminated array");
                char c = s.charAt(i++);
                if (c == ']') { depth--; return out; }
                if (c != ',') throw err("expected , or ]");
            }
        }

        Map<String, Object> object() throws IOException {
            if (++depth > 512) throw err("nesting too deep");
            i++;
            Map<String, Object> out = new LinkedHashMap<>();
            ws();
            if (i < s.length() && s.charAt(i) == '}') { i++; depth--; return out; }
            while (true) {
                ws();
                if (i >= s.length() || s.charAt(i) != '"') throw err("expected string key");
                String k = string();
                ws();
                if (i >= s.length() || s.charAt(i++) != ':') throw err("expected :");
                ws();
                out.put(k, value());
                ws();
                if (i >= s.length()) throw err("unterminated object");
                char c = s.charAt(i++);
                if (c == '}') { depth--; return out; }
                if (c != ',') throw err("expected , or }");
            }
        }
    }
}
