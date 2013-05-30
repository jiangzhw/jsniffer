package analyser;

import jpcap.packet.*;
import java.util.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferIPv6Dtls extends JSnifferPktDtls {

    private static final String[] valueNames = {
        "Version",
        "Class",
        "Flow Label",
        "Length",
        "Protocol",
        "Hop Limit",
        "Source IP",
        "Destination IP",
        "Source Host Name",
        "Destination Host Name"};
    Hashtable values = new Hashtable();

    public JSnifferIPv6Dtls() {
        layer = NETWORK_LAYER;
    }

    public boolean isInstance(Packet p) {
        if (p instanceof IPPacket && ((IPPacket) p).version == 6) {
            return true;
        } else {
            return false;
        }
    }

    public String getProtocol() {
        return "IPv6";
    }

    public String[] getPropertyNames() {
        return valueNames;
    }
    IPPacket ip;

    public void getDetails(Packet packet) {
        values.clear();
        if (!isInstance(packet)) {
            return;
        }
        ip = (IPPacket) packet;
        values.put(valueNames[0], new Integer(6));
        values.put(valueNames[1], new Integer(ip.priority));
        values.put(valueNames[2], new Integer(ip.flow_label));
        values.put(valueNames[3], new Integer(ip.length));
        values.put(valueNames[4], new Integer(ip.protocol));
        values.put(valueNames[5], new Integer(ip.hop_limit));
        values.put(valueNames[6], ip.src_ip.getHostAddress());
        values.put(valueNames[7], ip.dst_ip.getHostAddress());
        values.put(valueNames[8], ip.src_ip.getHostName());
        values.put(valueNames[9], ip.dst_ip.getHostName());
    }

    public Object getProperty(String propertyName) {
        return values.get(propertyName);
    }

    Object getPropertyAt(int index) {
        if (index < 0 || index >= valueNames.length) {
            return null;
        }
        return values.get(valueNames[index]);
    }

    public Object[] getProperties() {
        Object[] v = new Object[valueNames.length];

        for (int i = 0; i < valueNames.length; i++) {
            v[i] = values.get(valueNames[i]);
        }

        return v;
    }

    public String getInfo() {
        return "src:" + ip.src_ip.toString() + ", des:" + ip.dst_ip.toString();
    }
}
