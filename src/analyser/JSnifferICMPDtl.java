package analyser;

import jpcap.packet.ICMPPacket;
import jpcap.packet.Packet;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferICMPDtl extends JSnifferIPDtl {

    ICMPPacket icmp;

    public static boolean isInstance(Packet p) {
        return (p instanceof ICMPPacket);
    }

    public String getProtocol() {
        return "ICMP";
    }

    @Override
    public void setPacket(Packet p) {
        super.setPacket(p);
        icmp = (ICMPPacket) p;
    }

    public short getLiveTime() {
        return icmp.alive_time;
    }

    public byte getCode() {
        return icmp.code;
    }
}
