package analyser;

import jpcap.packet.IPPacket;
import jpcap.packet.Packet;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferIPv4Dtl extends JSnifferIPDtl {

    @Override
    public void setPacket(Packet packet) {
        super.setPacket(packet);
    }

    public static boolean isInstance(Packet p) {
        if (p instanceof IPPacket && ((IPPacket) p).version == 4) {
            return true;
        } else {
            return false;
        }
    }

    public boolean getDelay() {
        return p.d_flag;//delay
    }

    public boolean getFragment() {
        return p.dont_frag;	//don't fragment
    }

    public boolean getMorefragment() {
        return p.more_frag;//more fragment
    }

    public boolean getReliability() {
        return p.r_flag;//reliability
    }

    public boolean getReservation() {
        return p.rsv_frag;//fragmentation reservation
    }

    public boolean getThrough() {
        return p.t_flag;//getThrough
    }

    public int getIdentification() {
        return p.ident;
    }

    public int getFragmentOffset() {
        return p.offset;
    }

    public byte[] getOption() {
        return p.option;
    }
}
