package com.simtechdata.jtail;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.simtechdata.jtail.json.Json;
import com.simtechdata.jtail.tailcfg.Node;
import org.junit.jupiter.api.Test;

class NodeHomeDerpTest {
  private static Node parse(String json) throws Exception { return Node.fromJson(Json.parseObject(json)); }

  @Test void homeDerpField() throws Exception { assertEquals(7, parse("{\"HomeDERP\":7}").homeDerp); }
  @Test void legacyDerpString() throws Exception { assertEquals(9, parse("{\"DERP\":\"127.3.3.40:9\"}").homeDerp); }
  @Test void hostinfoNetInfo() throws Exception { assertEquals(17, parse("{\"Hostinfo\":{\"Hostname\":\"x\",\"NetInfo\":{\"PreferredDERP\":17}}}").homeDerp); }
  @Test void unknown() throws Exception { assertEquals(0, parse("{\"Hostinfo\":{\"Hostname\":\"x\"}}").homeDerp); }
}
