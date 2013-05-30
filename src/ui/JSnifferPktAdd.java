package ui;
import java.util.*;
import analyser.*;


/**
 * @author jiangzhw2008@yeah.net
 *
 */


public class JSnifferPktAdd
{
	static List<JSnifferPktDtls> analyzers=new ArrayList<JSnifferPktDtls>();
	static List<List<JSnifferPktDtls>> layerAnalyzers=new ArrayList<List<JSnifferPktDtls>>();
	
	static void loadDefaultAnalyzer(){
		analyzers.add(new JSnifferPktInfo());
		analyzers.add(new JSnifferEthernetDtls());
		analyzers.add(new JSnifferIPv4Dtls());
		analyzers.add(new JSnifferIPv6Dtls());
		analyzers.add(new JSnifferTCPDtls());
		analyzers.add(new JSnifferUDPDtls());
		analyzers.add(new JSnifferICMPDtls());
		
		for(int i=0;i<6;i++) {
            layerAnalyzers.add(new ArrayList<JSnifferPktDtls>());
        }
		
		for(JSnifferPktDtls a:analyzers) {
            layerAnalyzers.get(a.layer).add(a);
        }
	}
	
	public static List<JSnifferPktDtls> getAnalyzers(){
		return analyzers;
	}
	
	public static List<JSnifferPktDtls> getAnalyzersOf(int layer){
		return layerAnalyzers.get(layer);
	}
}
