import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
import java.net.Socket;

/**
 * Joins the tailnet as an ephemeral node, sends one line to <host>:7000 and prints the reply.
 *
 *   TS_AUTHKEY=tskey-auth-... java -cp target/classes examples/EchoClient.java my-echo-server "hello"
 */
public class EchoClient {
    public static void main(String[] args) throws Exception {
        String target = args.length > 0 ? args[0] : "jtail-echo";
        String message = args.length > 1 ? args[1] : "hello from jtail";
        try (Tailnet net = JTail.network().authKey(System.getenv("TS_AUTHKEY")).hostname("jtail-client-" + ProcessHandle.current().pid())
                .ephemeral(true).join()) {
            System.out.println("peers: " + net.peers().stream().map(p -> p.name()).toList());
            try (Socket s = net.dial(target, 7000)) {
                s.getOutputStream().write((message + "\n").getBytes());
                s.getOutputStream().flush();
                byte[] buf = new byte[4096];
                int n = s.getInputStream().read(buf);
                System.out.println("reply: " + new String(buf, 0, n).trim()
                        + (net.isDirect(target) ? "  [direct]" : "  [via DERP relay]"));
            }
        }
    }
}
