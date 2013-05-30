package analyser;

import jpcap.packet.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferFTPDtls extends JSnifferPktDtls {

    public JSnifferFTPDtls() {
        layer = APPLICATION_LAYER;
    }

    public boolean isInstance(Packet p) {
        if (p instanceof TCPPacket &&
                (((TCPPacket) p).src_port == 20 || ((TCPPacket) p).dst_port == 20 ||
                ((TCPPacket) p).src_port == 21 || ((TCPPacket) p).dst_port == 21)) {
            return true;
        } else {
            return false;
        }
    }

    public String getProtocol() {
        return "FTP";
    }

    public String[] getPropertyNames() {
        return null;
    }

    public void getDetails(Packet p) {
    }

    public Object getProperty(String s) {
        return null;
    }

    public Object getPropertyAt(int i) {
        return null;
    }

    public Object[] getProperties() {
        return null;
    }

    public String getInfo() {
        return "";
    }
}
