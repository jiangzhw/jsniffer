package analyser;
import jpcap.packet.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */


public class JSnifferUDPDtls extends JSnifferPktDtls
{
	private static final String[] valueNames={
		"Source Port",
		"Destination Port",
	};
	private UDPPacket udp;
	
	public JSnifferUDPDtls(){
		layer=TRANSPORT_LAYER;
	}
	
	public boolean isInstance(Packet p){
		return (p instanceof UDPPacket);
	}
	
	public String getProtocol(){
		return "UDP";
	}
	
	public String[] getPropertyNames(){
		return valueNames;
	}
	
	public void getDetails(Packet p){
		if(!isInstance(p)) {
            return;
        }
		udp=(UDPPacket)p;
	}
	
	public Object getProperty(String propertyName){
		for(int i=0;i<valueNames.length;i++) {
            if (valueNames[i].equals(propertyName)) {
                return getPropertyAt(i);
            }
        }
		
		return null;
	}
	
	public Object getPropertyAt(int index){
		switch(index){
			case 0: return new Integer(udp.src_port);
			case 1: return new Integer(udp.dst_port);
			default: return null;
		}
	}
	
	public Object[] getProperties(){
		Object[] v=new Object[2];
		for(int i=0;i<2;i++) {
            v[i] = getPropertyAt(i);
        }
		
		return v;
	}
	public String getInfo(){
		return "source port:"+udp.src_port+", destination port:"+udp.dst_port;
	}
}
