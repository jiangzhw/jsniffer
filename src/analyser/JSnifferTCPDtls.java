package analyser;

import jpcap.packet.*;
import java.util.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferTCPDtls extends JSnifferPktDtls {

    private static final String[] valueNames = {
        "Source Port",
        "Destination Port",
        "Sequence Number",
        "Ack Number",
        "URG Flag",
        "ACK Flag",
        "PSH Flag",
        "RST Flag",
        "SYN Flag",
        "FIN Flag",
        "Window Size"};
    Hashtable values = new Hashtable();

    public JSnifferTCPDtls() {
        layer = TRANSPORT_LAYER;
    }

    public boolean isInstance(Packet p) {
        return (p instanceof TCPPacket);
    }

    public String getProtocol() {
        return "TCP";
    }

    public String[] getPropertyNames() {
        return valueNames;
    }
    TCPPacket tcp;

    public void getDetails(Packet p) {
        values.clear();
        if (!isInstance(p)) {
            return;
        }
        tcp = (TCPPacket) p;
        values.put(valueNames[0], new Integer(tcp.src_port));
        values.put(valueNames[1], new Integer(tcp.dst_port));
        values.put(valueNames[2], new Long(tcp.sequence));
        values.put(valueNames[3], new Long(tcp.ack_num));
        values.put(valueNames[4], new Boolean(tcp.urg));
        values.put(valueNames[5], new Boolean(tcp.ack));
        values.put(valueNames[6], new Boolean(tcp.psh));
        values.put(valueNames[7], new Boolean(tcp.rst));
        values.put(valueNames[8], new Boolean(tcp.syn));
        values.put(valueNames[9], new Boolean(tcp.fin));
        values.put(valueNames[10], new Integer(tcp.window));
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
        return "source port:" + tcp.src_port + ", destination port:" + tcp.dst_port;
    }
}
