package analyser;

import jpcap.packet.Packet;
import jpcap.packet.ARPPacket;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferARPDtl extends JSnifferEthernetDtl {

    ARPPacket arppacket;
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
    /** Hardware type: Ethernet */
    public static final short HARDTYPE_ETHER = 1;
    /** Hardware type: Token ring */
    public static final short HARDTYPE_IEEE802 = 6;
    /** Hardware type: Frame relay */
    public static final short HARDTYPE_FRAMERELAY = 15;
    /** Protocol type: IP */
    public static final short PROTOTYPE_IP = 2048;

    @Override
    public void setPacket(Packet packet) {
        this.arppacket = (ARPPacket) packet;
        super.setPacket(packet);
    }

    public static boolean isInstance(Packet packet) {
        return (packet instanceof ARPPacket);
    }

    public String getProtocol() {
        return "ARP(/RAPR)";
    }

    public String getARPtoString() {
        return arppacket.toString();
    }

    public String getHardtype() {
        switch (arppacket.hardtype) {
            case HARDTYPE_ETHER:
                return "ARP REQUEST ";
            case HARDTYPE_IEEE802:
                return "ARP REPLY ";
            case HARDTYPE_FRAMERELAY:
                return "RARP REQUEST ";
            default:
                return "UNKNOWN ";
        }
    }

    public String getPrototype() {
        switch (arppacket.prototype) {
            case PROTOTYPE_IP:
                return "IP";
            default:
                return "Unknown";
        }
    }

    public Short getHardwareAddressLength() {
        return arppacket.hlen;
    }

    public Short getProtocolAddressLength() {
        return arppacket.plen;
    }

    public int getProtocoltype() {
        return arppacket.prototype;
    }

    public String getOperation() {
        switch (arppacket.operation) {
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

    public Object getSenderHardwareAddress() {
        return arppacket.getSenderHardwareAddress();
    }

    public Object getSenderProtocolAddress() {
        return arppacket.getSenderProtocolAddress().toString().replace("/", "");
    }

    public Object getTargetHardwareAddress() {
        return arppacket.getTargetHardwareAddress();
    }

    public Object getTargetProtocolAddress() {
        return arppacket.getTargetProtocolAddress().toString().replace("/", "");
    }

    public String getInfo() {
        switch (arppacket.operation) {
            case ARP_REQUEST:
                return "who has " + getTargetProtocolAddress() + " tell " + getSenderProtocolAddress();
            case ARP_REPLY:
                return getSenderProtocolAddress() + " is at " + getSenderHardwareAddress();
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
