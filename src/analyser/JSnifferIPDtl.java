package analyser;

import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import java.net.InetAddress;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferIPDtl extends JSnifferEthernetDtl {

    IPPacket p;
    /** Protocol number for ICMP */
    public static final short IPPROTO_ICMP = 1;
    /** Protocol number for IGMP */
    public static final short IPPROTO_IGMP = 2;
    /** Protocol number for IP in IP */
    public static final short IPPROTO_IP = 4;
    /** Protocol number for TCP */
    public static final short IPPROTO_TCP = 6;
    /** Protocol number for UDP */
    public static final short IPPROTO_UDP = 17;
    /** Protocol number for IPv6 */
    public static final short IPPROTO_IPv6 = 41;
    /** Protocol number for IPv6 hop-by-hop option */
    public static final short IPPROTO_HOPOPT = 0;
    /** Protocol number for routing header for IPv6 */
    public static final short IPPROTO_IPv6_Route = 43;
    /** Protocol number for fragment header for IPv6 */
    public static final short IPPROTO_IPv6_Frag = 44;
    /** Protocol number for IPv6 ICMP */
    public static final short IPPROTO_IPv6_ICMP = 58;
    /** Protocol number for no next header header for IPv6 */
    public static final short IPPROTO_IPv6_NoNxt = 59;
    /** Protocol number for destination option for IPv6 */
    public static final short IPPROTO_IPv6_Opts = 60;

    public static boolean isInstance(Packet packet) {
        return (packet instanceof IPPacket);
    }

    @Override
    public void setPacket(Packet packet) {
        this.p = (IPPacket) packet;
        super.setPacket(packet);
    }

    public InetAddress getDestinationIPaddress() {
        return p.dst_ip;
    }

    public InetAddress getSourceIPaddress() {
        return p.src_ip;
    }

    public String getPrototype() {
        switch (p.protocol) {
            case IPPROTO_ICMP:
                return "ICMP";
            case IPPROTO_IGMP:
                return "IGMP";
            case IPPROTO_TCP:
                return "TCP";
            case IPPROTO_UDP:
                return "UDP";
            case IPPROTO_IPv6:
                return "IPv6";
            case IPPROTO_IPv6_Route:
                return "IPv6";
            case IPPROTO_HOPOPT:
                return "IPv6";
            case IPPROTO_IPv6_Frag:
                return "IPv6";
            case IPPROTO_IPv6_ICMP:
                return "ICMP(IPv6)";
            case IPPROTO_IPv6_NoNxt:
                return "IPv6";
            case IPPROTO_IPv6_Opts:
                return "IPv6";
            default:
                return "UNKNOWN ";
        }
    }

    public short getTimeToLive() {
        return p.hop_limit;
    }

    public String getIPVersion() {
        switch (p.version) {
            case 4:
                return "IPv4";
            case 6:
                return "IPv6";
            default:
                return "UNKNOWN ";
        }
    }

    public byte getPiority() {
        return p.priority;
    }

    public byte getServiceType() {
        return p.rsv_tos;
    }

    public String getInfo() {

        if (JSnifferUDPDtl.isInstance(p)) {
            JSnifferUDPDtl t = new JSnifferUDPDtl();
            t.setPacket(p);
            return "Source Port: " + t.getSourcePort() + "  Destination Port:" + t.getDestinationPort();
        } else if (JSnifferTCPDtl.isInstance(p)) {
            JSnifferTCPDtl t = new JSnifferTCPDtl();
            t.setPacket(p);
            return "Source Port: " + t.getSourcePort() + "  Destination Port:" + t.getDestinationPort();
        } else if (JSnifferICMPDtl.isInstance(p)) {
            JSnifferICMPDtl t = new JSnifferICMPDtl();
            t.setPacket(p);
            return "LiveTime: " + t.getLiveTime() + " code: " + t.getCode();

        } else {
            return "Version:" + this.getIPVersion();
        }
    }
}
