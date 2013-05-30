package analyser;

import java.net.InetAddress;
import java.util.Hashtable;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
/**
 * @author Administrator
 *
 */
public class JSnifferIPv4Dtls extends JSnifferPktDtls {

    private static final String[] valueNames = {"Version",
        "TOS: Priority",
        "TOS: Throughput",
        "TOS: Reliability",
        "Length",
        "Identification",
        "Fragment: Don't Fragment",
        "Fragment: More Fragment",
        "Fragment Offset",
        "Time To Live",
        "Protocol",
        "Source IP",
        "Destination IP",
        "Source Host Name",
        "Destination Host Name"};
    private Hashtable values = new Hashtable();

    public JSnifferIPv4Dtls() {
        layer = NETWORK_LAYER;
    }

    public boolean isInstance(Packet p) {
        if (p instanceof IPPacket && ((IPPacket) p).version == 4) {
            return true;
        } else {
            return false;
        }
    }

    public String getProtocol() {
        return "IPv4";
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
        values.put(valueNames[0], new Integer(4));
        values.put(valueNames[1], new Integer(ip.priority));
        values.put(valueNames[2], new Boolean(ip.t_flag));
        values.put(valueNames[3], new Boolean(ip.r_flag));
        values.put(valueNames[4], new Integer(ip.length));
        values.put(valueNames[5], new Integer(ip.ident));
        values.put(valueNames[6], new Boolean(ip.dont_frag));
        values.put(valueNames[7], new Boolean(ip.more_frag));
        values.put(valueNames[8], new Integer(ip.offset));
        values.put(valueNames[9], new Integer(ip.hop_limit));
        values.put(valueNames[10], new Integer(ip.protocol));
        values.put(valueNames[11], ip.src_ip.getHostAddress());
        values.put(valueNames[12], ip.dst_ip.getHostAddress());
        values.put(valueNames[13], ip.src_ip);
        values.put(valueNames[14], ip.dst_ip);
    }

    public Object getProperty(String propertyName) {
        if ((valueNames[13].equals(propertyName) && values.get(propertyName) instanceof InetAddress) ||
                (valueNames[14].equals(propertyName) && values.get(propertyName) instanceof InetAddress)) {

            InetAddress addr = (InetAddress) values.get(propertyName);
            if (JSnifferCaptor.hostnameCache.containsKey(addr)) {
                values.put(propertyName, JSnifferCaptor.hostnameCache.get(addr));
            } else {
                values.put(propertyName, addr.getHostName());
                System.out.println("miss");
            }
        }

        return values.get(propertyName);
    }

    Object getPropertyAt(int index) {
        if (index < 0 || index >= valueNames.length) {
            return null;
        }

        return getProperty(valueNames[index]);
    }

    public Object[] getProperties() {
        Object[] v = new Object[valueNames.length];

        for (int i = 0; i < valueNames.length; i++) {
            v[i] = getPropertyAt(i);
        }

        return v;
    }

    public String getInfo() {
        return "src:" + ip.src_ip.toString() + ", des:" + ip.dst_ip.toString();
    }
}
