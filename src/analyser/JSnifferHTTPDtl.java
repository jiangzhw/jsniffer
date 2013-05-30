package analyser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Vector;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferHTTPDtl extends JSnifferTCPDtl {

    String method;
    Vector headers = new Vector();

    public static boolean isInstance(Packet p) {
        if (p instanceof TCPPacket &&
                (((TCPPacket) p).src_port == 80 || ((TCPPacket) p).dst_port == 80)) {
            return true;
        } else {
            return false;
        }
    }

    public Vector getHeaders() {
        return headers;
    }

    public String getProtocol() {
        return "HTTP";
    }

    public String getMethod() {
        return method;
    }

    @Override
    public void setPacket(Packet p) {
        super.setPacket(p);
        method = "";
        headers.removeAllElements();
        if (!isInstance(p)) {
            return;
        }

        try {
            BufferedReader in = new BufferedReader(new StringReader(new String(p.data)));

            method = in.readLine();
            if (method == null || method.indexOf("HTTP") == -1) {
                method = "Not HTTP Header";
                return;
            }

            String l;
            //read headers
            while ((l = in.readLine()).length() > 0) {
                headers.addElement(l);
            }
        } catch (IOException e) {
        }
    }
}
