package analyser;

import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import java.util.List;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferIPv6Dtl extends JSnifferIPDtl {

    public void setPacket(Packet packet) {
        super.setPacket(packet);
    }

    public static boolean isInstance(Packet p) {
        if (p instanceof IPPacket && ((IPPacket) p).version == 6) {
            return true;
        } else {
            return false;
        }
    }

    public int getFlowLabel() {
        return p.flow_label;
    }

    public List getOptions() {
        return p.options;
    }
}
