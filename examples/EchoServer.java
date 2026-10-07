import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;

/**
 * Joins the tailnet and runs a TCP echo server on port 7000.
 *
 *   TS_AUTHKEY=tskey-auth-... java -cp target/classes examples/EchoServer.java my-echo-server
 */
public class EchoServer {
    public static void main(String[] args) throws Exception {
        String hostname = args.length > 0 ? args[0] : "jtail-echo";
        try (Tailnet net = JTail.network()
                .authKey(System.getenv("TS_AUTHKEY"))
                .hostname(hostname)
                .stateDir(Path.of(System.getProperty("user.home"), ".jtail", hostname))
                .join();
             ServerSocket server = net.listen(7000)) {
            System.out.println("Listening on " + net.name() + " (" + net.address().getHostAddress() + "):7000");
            while (true) {
                Socket s = server.accept();
                System.out.println("connection from " + s.getInetAddress().getHostAddress());
                Thread.ofVirtual().start(() -> {
                    try (s) {
                        s.getInputStream().transferTo(s.getOutputStream());
                    } catch (Exception e) {
                        System.out.println("connection ended: " + e);
                    }
                });
            }
        }
    }
}
