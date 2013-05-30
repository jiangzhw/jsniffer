package analyser;
import jpcap.packet.*;

/**
 * @author Administrator
 *
 */

public class JSnifferPktInfo extends JSnifferPktDtls
{
	private static final String[] valueNames={"Arrival Time","Frame Length","Captured Length"};
	private Packet packet;
	
	public boolean isInstance(Packet packet){
		return true;
	}
	
	public String getProtocol(){
		return "Frame";
	}
	
	public String[] getPropertyNames(){
		  return valueNames;
	}
	
	public void getDetails(Packet p){
		packet=p;
	}
	
	public Object getProperty(String name){
		if(name.equals(valueNames[0])) {
            return new java.util.Date(packet.sec * 1000 + packet.usec / 1000).toString();
        }
		else if(name.equals(valueNames[1])) {
            return new Integer(packet.len);
        }
		else if(name.equals(valueNames[2])) {
            return new Integer(packet.caplen);
        }
		else {
            return null;
        }
	}
	
	Object getPropertyAt(int index){
		switch(index){
			case 0: return new java.util.Date(packet.sec*1000+packet.usec/1000).toString();
			case 1: return new Integer(packet.len);
			case 2: return new Integer(packet.caplen);
			default: return null;
		}
	}
	
	public Object[] getProperties(){
		Object[] v=new Object[3];
		v[0]=new java.util.Date(packet.sec*1000+packet.usec/1000).toString();
		v[1]=new Integer(packet.len);
		v[2]=new Integer(packet.caplen);
		
		return v;
	}
	
	public String getInfo()
	{
		return packet.len+" bytes on wire, "+packet.caplen+" bytes captured";
	}
}