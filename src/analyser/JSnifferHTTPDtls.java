package analyser;

import jpcap.packet.*;
import java.util.*;
import java.io.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferHTTPDtls extends JSnifferPktDtls {

    private static final String[] valueNames = {
        "Data Length",
        "Method",
        "Header"
    };
    String method;
    Vector headers = new Vector();

    public JSnifferHTTPDtls() {
        layer = APPLICATION_LAYER;
    }
    TCPPacket ptemp;

    public boolean isInstance(Packet p) {
        if (p instanceof TCPPacket &&
                (((TCPPacket) p).src_port == 80 || ((TCPPacket) p).dst_port == 80)) {
            ptemp = (TCPPacket) p;
            return true;
        } else {
            return false;
        }
    }

    public String getProtocol() {
        return "Hypertext Transfer Protocol";
    }

    public String[] getPropertyNames() {
        return valueNames;
    }

    public void getDetails(Packet p) {
        method = "";
        headers.removeAllElements();
        if (!isInstance(p)) {
            return;
        }

        try {
            BufferedReader in = new BufferedReader(new StringReader(new String(p.data)));

            method = in.readLine();
            if (method == null || method.indexOf("HTTP") == -1) {
                // this packet doesn't contain HTTP header
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

    public Object getProperty(String propertyName) {
        if (valueNames[0].equals(propertyName)) {
            return ptemp.data.length;
        }
        if (valueNames[1].equals(propertyName)) {
            return method;
        }
        if (valueNames[2].equals(propertyName)) {
            return headers;
        }
        return null;
    }

    Object getPropertyAt(int index) {
        if (index == 0) {
            return ptemp.data.length;
        }
        if (index == 1) {
            return method;
        }
        if (index == 2) {
            return headers;
        }
        return null;
    }

    public Object[] getProperties() {
        Object[] values = new Object[3];
        values[0] = ptemp.data.length;
        values[1] = method;
        values[2] = headers;

        return values;
    }

    public String getInfo() {
        return "Data:" + ptemp.data.length + " bytes";
    }
}
