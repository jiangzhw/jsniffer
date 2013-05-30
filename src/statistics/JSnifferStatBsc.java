package statistics;

import java.util.List;
import jpcap.packet.Packet;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public abstract class JSnifferStatBsc {

    public abstract String getName();

    public abstract String[] getLabels();

    public abstract String[] getStatTypes();

    public abstract long[] getValues(int index);

    public abstract void take(List<Packet> packets);

    public abstract void addPacket(Packet p);

    public abstract void clear();

    public JSnifferStatBsc newInstance() {
        try {
            return (JSnifferStatBsc) this.getClass().newInstance();
        } catch (Exception e) {
            return null;
        }
    }
}