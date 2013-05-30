package analyser;

import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferEthernetDtl extends JSnifferPktBscDtl {

    EthernetPacket eth;

    @Override
    public void setPacket(Packet packet) {
        super.setPacket(packet);
        eth = (EthernetPacket) packet.datalink;
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

    public static boolean isInstance(Packet p) {
        return (p.datalink != null && p.datalink instanceof EthernetPacket);
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
