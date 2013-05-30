package analyser;

import jpcap.packet.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferARPDtls extends JSnifferPktDtls {

    public static final short ARP_REQUEST = 1;
    /** ARP reply */
    public static final short ARP_REPLY = 2;
    /** Reverse ARP request */
    public static final short RARP_REQUEST = 3;
    /** Reverse ARP reply */
    public static final short RARP_REPLY = 4;
    /** Identify peer request */
    public static final short INV_REQUEST = 8;
    /** Identify peer response */
    public static final short INV_REPLY = 9;
    private static final String[] valueNames = {
        "Hardware Type",
        "Protocol Type",
        "Hardware Address Length",
        "Protocol Address Length",
        "Operation",
        "Sender Hardware Address",
        "Sender Protocol Address",
        "Target Hardware Address",
        "Target Protocol Address"
    };
    private ARPPacket arp;

    public JSnifferARPDtls() {
        layer = NETWORK_LAYER;
    }

    public boolean isInstance(Packet p) {
        return (p instanceof ARPPacket);
    }

    public String getProtocol() {
        return "Address Resolution Protocol";
    }

    public String[] getPropertyNames() {
        return valueNames;
    }

    public void getDetails(Packet p) {
        if (!isInstance(p)) {
            return;
        }
        arp = (ARPPacket) p;
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
            case 0:
                switch (arp.hardtype) {
                    case ARPPacket.HARDTYPE_ETHER:
                        return "Ethernet (" + arp.hardtype + ")";
                    case ARPPacket.HARDTYPE_IEEE802:
                        return "Token ring (" + arp.hardtype + ")";
                    case ARPPacket.HARDTYPE_FRAMERELAY:
                        return "Frame relay (" + arp.hardtype + ")";
                    default:
                        return new Integer(arp.hardtype);
                }
            case 1:
                switch (arp.prototype) {
                    case ARPPacket.PROTOTYPE_IP:
                        return "IP (" + arp.prototype + ")";
                    default:
                        return new Integer(arp.prototype);
                }
            case 2:
                return new Integer(arp.hlen);
            case 3:
                return new Integer(arp.plen);
            case 4:
                switch (arp.operation) {
                    case ARPPacket.ARP_REQUEST:
                        return "ARP Request";
                    case ARPPacket.ARP_REPLY:
                        return "ARP Reply";
                    case ARPPacket.RARP_REQUEST:
                        return "Reverse ARP Request";
                    case ARPPacket.RARP_REPLY:
                        return "Reverse ARP Reply";
                    case ARPPacket.INV_REQUEST:
                        return "Identify peer Request";
                    case ARPPacket.INV_REPLY:
                        return "Identify peer Reply";
                    default:
                        return new Integer(arp.operation);
                }
            case 5:
                return arp.getSenderHardwareAddress();
            case 6:
                return arp.getSenderProtocolAddress();
            case 7:
                return arp.getTargetHardwareAddress();
            case 8:
                return arp.getTargetProtocolAddress();
            default:
                return null;
        }
    }

    public Object[] getProperties() {
        Object[] v = new Object[valueNames.length];
        for (int i = 0; i < valueNames.length; i++) {
            v[i] = getPropertyAt(i);
        }

        return v;
    }

    public String getInfo() {
        switch (arp.operation) {
            case ARP_REQUEST:
                return "ARP REQUEST ";
            case ARP_REPLY:
                return "ARP REPLY ";
            case RARP_REQUEST:
                return "RARP REQUEST ";
            case RARP_REPLY:
                return "RARP REPLY ";
            case INV_REQUEST:
                return "IDENTIFY REQUEST ";
            case INV_REPLY:
                return "IDENTIFY REPLY ";
            default:
                return "UNKNOWN ";
        }
    }
}
