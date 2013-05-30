package analyser;

import java.text.SimpleDateFormat;
import jpcap.packet.Packet;
import jpcap.packet.DatalinkPacket;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferPktBscDtl {

    protected Packet packet;

    public static boolean isInstance(Packet packet) {
        return true;
    }

    public void setPacket(Packet packet) {
        this.packet = packet;
    }

    public int getCapturedLength() {
        return packet.caplen;
    }

    public Object getPacketLength() {
        return new Integer(packet.len);
    }


    public Object getTime() {
       java.util.Date time=new java.util.Date(packet.sec * 1000 + packet.usec / 1000);
       SimpleDateFormat formatter = new SimpleDateFormat("HH:mm:ss:SS yyyy-MM-dd");
       String dateString = formatter.format(time);
        return dateString;

    }

    public byte[] getHeader() {
        return packet.header;
    }

    public byte[] getData() {
        return packet.data;
    }

    public DatalinkPacket getDatalink() {
        return packet.datalink;
    }
}
