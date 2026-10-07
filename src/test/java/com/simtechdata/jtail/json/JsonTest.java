package com.simtechdata.jtail.json;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JsonTest {
    @Test
    void parsesAllTypes() throws Exception {
        Map<String, Object> m = Json.parseObject(
                "{\"a\":1,\"b\":-2.5e1,\"c\":\"x\\ny\\u00e9\\\"\",\"d\":[true,false,null],\"e\":{},\"big\":9007199254740993}");
        assertEquals(1L, m.get("a"));
        assertEquals(-25.0, m.get("b"));
        assertEquals("x\nyé\"", m.get("c"));
        assertEquals(List.of(true, false), ((List<?>) m.get("d")).subList(0, 2));
        assertNull(((List<?>) m.get("d")).get(2));
        assertEquals(9007199254740993L, m.get("big")); // int64 precision preserved
    }

    @Test
    void roundTrip() throws Exception {
        String src = "{\"k\":[1,2,{\"z\":\"q\\\\\"}],\"s\":\"\\u0001tab\\t\",\"n\":null}";
        assertEquals(Json.parse(src), Json.parse(Json.write(Json.parse(src))));
    }

    @Test
    void rejectsGarbage() {
        for (String bad : new String[]{"{", "[1,]", "{\"a\" 1}", "tru", "\"abc", "{} x", "[1 2]", "\"\\q\""}) {
            assertThrows(IOException.class, () -> Json.parse(bad), bad);
        }
    }

    @Test
    void accessorsAreNullTolerant() throws Exception {
        Map<String, Object> m = Json.parseObject("{\"n\":5,\"s\":\"v\",\"l\":[\"a\",\"b\"]}");
        assertEquals(0, J.lng(m, "missing"));
        assertEquals("", J.str(m, "n"));
        assertEquals(List.of("a", "b"), J.strings(m, "l"));
        assertNull(J.optBool(m, "missing"));
        assertTrue(J.list(m, "nope").isEmpty());
    }

    @Test
    void writesBytesAsBase64AndEscapesControl() {
        assertEquals("\"AQID\"", Json.write(new byte[]{1, 2, 3}));
        assertEquals("\"\\u0001\"", Json.write("\u0001"));
    }
}
