package analyser;

import jpcap.packet.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferEthernetDtls extends JSnifferPktDtls {

    private static final String[] valueNames = {
        "Source",
        "Destination",
        "Frame Type"
    };
    private EthernetPacket eth;

    public JSnifferEthernetDtls() {
        layer = DATALINK_LAYER;
    }

    public boolean isInstance(Packet p) {
        return (p.datalink != null && p.datalink instanceof EthernetPacket);
    }

    public String getProtocol() {
        return "Ethernet Frame";
    }

    public String[] getPropertyNames() {
        return valueNames;
    }

    public void getDetails(Packet p) {
        if (!isInstance(p)) {
            return;
        }
        eth = (EthernetPacket) p.datalink;
    }

    public Object getProperty(String propertyName) {
        for (int i = 0; i < valueNames.length; i++) {
            if (valueNames[i].equals(propertyName)) {
                return getPropertyAt(i);
            }
        }

        return null;
    }

    Object getPropertyAt(int index) {
        switch (index) {
            case 2:
                return new Integer(eth.frametype);
            case 0:
                return eth.getSourceAddress();
            case 1:
                return eth.getDestinationAddress();
            default:
                return null;
        }
    }

    public Object[] getProperties() {
        Object[] v = new Object[3];
        for (int i = 0; i < 3; i++) {
            v[i] = getPropertyAt(i);
        }

        return v;
    }

    public String getInfo() {
        return "src:" + getSourceHardwareAddress() + " des:" + getDestinationHardwareAddress();
    }

    public byte[] getSourceMAC() {
        return eth.dst_mac;
    }

    public String getSourceHardwareAddress() {
        char[] adr = new char[17];

        for (int i = 0; i < 5; i++) {
            adr[i * 3] = hexUpperChar(eth.dst_mac[i]);
            adr[i * 3 + 1] = hexLowerChar(eth.dst_mac[i]);
            adr[i * 3 + 2] = ':';
        }
        adr[15] = hexUpperChar(eth.dst_mac[5]);
        adr[16] = hexLowerChar(eth.dst_mac[5]);

        return new String(adr);
    }

    public byte[] getDestinationMAC() {
        return eth.src_mac;
    }

    public String getDestinationHardwareAddress() {
        char[] adr = new char[17];

        for (int i = 0; i < 5; i++) {
            adr[i * 3] = hexUpperChar(eth.src_mac[i]);
            adr[i * 3 + 1] = hexLowerChar(eth.src_mac[i]);
            adr[i * 3 + 2] = ':';
        }
        adr[15] = hexUpperChar(eth.src_mac[5]);
        adr[16] = hexLowerChar(eth.src_mac[5]);

        return new String(adr);
    }

    private char hexUpperChar(byte b) {
        b = (byte) ((b >> 4) & 0xf);
        if (b == 0) {
            return '0';
        } else if (b < 10) {
            return (char) ('0' + b);
        } else {
            return (char) ('a' + b - 10);
        }
    }

    private char hexLowerChar(byte b) {
        b = (byte) (b & 0xf);
        if (b == 0) {
            return '0';
        } else if (b < 10) {
            return (char) ('0' + b);
        } else {
            return (char) ('a' + b - 10);
        }
    }
}
