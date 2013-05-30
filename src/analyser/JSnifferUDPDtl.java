package analyser;

import jpcap.packet.Packet;
import jpcap.packet.UDPPacket;
/**
 * @author jiangzhw2008@yeah.net
 *
 */


public class JSnifferUDPDtl extends JSnifferIPDtl{

	UDPPacket udp;
	
	public static boolean isInstance(Packet p){
		return (p instanceof UDPPacket);
	}
	
    @Override
	public void setPacket(Packet packet)
	{
		super.setPacket(packet);
		udp=(UDPPacket)packet;
	}

	public void getDetails(Packet p){
		if(!isInstance(p)) {
            return;
        }
		udp=(UDPPacket)p;
	}
	
	public int getDestinationPort()
	{
		return udp.dst_port;
	}
	
	public int getSourcePort()
	{
		return udp.src_port;
	}
}
