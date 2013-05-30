package analyser;

import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

/**
 * @author jiangzhw2008@yeah.net
 *
 */

public class JSnifferTCPDtl extends JSnifferIPDtl {

    TCPPacket tcp;

    public static boolean isInstance(Packet p) {
        return (p instanceof TCPPacket);
    }

    @Override
    public void setPacket(Packet packet) {
        super.setPacket(packet);
        tcp = (TCPPacket) p;
    }

    public int getSourcePort() {
        return tcp.src_port;
    }

    public int getDestinationPort() {
        return tcp.dst_port;
    }

    public long getSequenceNumber() {
        return tcp.sequence;
    }

    public long getACKNumber() {
        return tcp.ack_num;
    }

    public boolean getACKFlag() {
        return tcp.ack;
    }

    public boolean getPSHFlag() {
        return tcp.psh;
    }

    public boolean getRSTFlag() {
        return tcp.rst;
    }

    public boolean getSYNFlag() {
        return tcp.syn;
    }

    public boolean getFINFlag() {
        return tcp.fin;
    }

    public int getWindowSize() {
        return tcp.window;
    }
}
