package analyser;
import jpcap.packet.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */

public abstract class JSnifferPktDtls
{
	public int layer=DATALINK_LAYER;
	public static int DATALINK_LAYER=0;
	public static int NETWORK_LAYER=1;
	public static int TRANSPORT_LAYER=2;
	public static int APPLICATION_LAYER=3;
	
	public abstract boolean isInstance(Packet packet);
	public abstract void getDetails(Packet packet);
	public abstract String getProtocol();
	public abstract String[] getPropertyNames();
	public abstract Object getProperty(String propertyName);
	abstract Object getPropertyAt(int index);
	public abstract Object[] getProperties();
	public abstract String getInfo();
}
