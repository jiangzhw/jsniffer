package analyser;

import jpcap.packet.*;
import javax.swing.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferPktDataDtl extends JTextArea {

    public JSnifferPktDataDtl() {
        super();

        setLineWrap(true);
        setEditable(false);
    }

    public void packetData(Packet p) {
        byte[] packetdata = new byte[p.header.length + p.data.length];
        // byte[] packetdata1 = new byte[p.header.length + p.data.length];
        System.arraycopy(p.header, 0, packetdata, 0, p.header.length);
        System.arraycopy(p.data, 0, packetdata, p.header.length, p.data.length);
      //  packetdata1 =packetdata.getBytes("iso-8859-1")

        StringBuffer buf = new StringBuffer();


    
        for (int i = 0, j; i < packetdata.length;) {
         /*   for(j=0;j<8 && i<packetdata.length;j++,i++){
				String d=Integer.toHexString((int)(packetdata[i]&0xff));
				buf.append((d.length()==1?"0"+d:d)+" ");
			 if(packetdata[i]<32 || packetdata[i]>126) packetdata[i]=46;
			}
			buf.append("\t"+new String(packetdata,i-j,j)+"\n");
        }*/
           buf.append("000000" + i / 16 + "0\t");
            for (j = 0; j < 16 && i < packetdata.length; j++, i++) {
                String d = Integer.toHexString((int) (packetdata[i] & 0xff));
                buf.append((d.length() == 1 ? "0" + d : d) + " ");
                if (packetdata[i] < 32 || packetdata[i] > 126) {
                    packetdata[i] = 46;
                }
            }

            try {
                //buf.append("\t" + new String(packetdata, i - j, j)+ "\t");
                 buf.append("\t" + new String(packetdata, i - j, j, "GBK") + "\t");
                buf.append("\t" + new String(packetdata, i - j, j, "UTF-8") + "\n");
            } catch (Exception e) {
                e.printStackTrace();
            }

        }

        this.setText(buf.toString());
        this.setCaretPosition(0);
    }
}
