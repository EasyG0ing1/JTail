import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;

/** No auth key: prints a URL to open in a browser and waits for you to approve the node. */
public class InteractiveLogin {
    public static void main(String[] args) throws Exception {
        try (Tailnet net = JTail.network()
                .hostname("jtail-interactive")
                .onLoginRequired(url -> System.out.println("To authorize this node, open: " + url))
                .join()) {
            System.out.println("Joined as " + net.name() + " at " + net.address().getHostAddress());
            net.peers().forEach(p -> System.out.println(" peer " + p.name() + " " + p.addresses() + (p.online() ? " online" : "")));
        }
    }
}
