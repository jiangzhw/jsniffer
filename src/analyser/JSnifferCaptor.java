package analyser;

import statistics.JSnifferStatBsc;
import ui.*;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import jpcap.JpcapCaptor;
import jpcap.PacketReceiver;
import jpcap.JpcapWriter;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import java.text.SimpleDateFormat;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferCaptor {

    private static JSnifferOpt option;
    public javax.swing.JFileChooser chooser;
    private List<Packet> packets = new ArrayList<Packet>();
    private JpcapCaptor jpcap = null;
    public boolean isRun;
    private Thread captureThread;
    private JSnifferFrame frame;
    public long SAVE_NUMBER = 20000;
    public long numOfPs;
    public long sizeOfPs;
    public Date first;
    public Date last;
    private JpcapWriter writer = null;
    private String filename = null;

    //start writer
    public void startWriter() {
        Date date = new Date();
        SimpleDateFormat formater = new SimpleDateFormat();
        formater.applyPattern("yyyy-M-dd");

        if (writer != null) {
            while (packets.size() > 0) {
                writer.writePacket(packets.get(0));
                packets.remove(0);
            }
            writer.close();
        
        }

        filename = formater.format(date) + jpcap.toString() + ".dat";

        try {
            writer = JpcapWriter.openDumpFile(jpcap, option.filePathField + filename);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    //restart writer, when writer is save some data before ,add that to end file
    public void restartWriter() {
        if (writer != null) {
            while (packets.size() > 0) {
                writer.writePacket(packets.get(0));
                packets.remove(0);
            }
        }

    

    }

    public void setFrame(JSnifferFrame frame) {
        this.frame = frame;
    }

    public List<Packet> getPackets() {
        return packets;
    }

    public JSnifferOpt getOptions() {
        return option;
    }

    public void capturePackets() {
        if (jpcap != null) {
            jpcap.close();
        }

        option = JSnifferCapOptDlg.getJpcap(frame);

        try {
            jpcap = JpcapCaptor.openDevice(option.getTheinterface(), option.getMaxlength(), option.isPromiscuous(), 50);
            if (option.filterField != null) {
                jpcap.setFilter(option.filterField, true);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        clear();


        SimpleDateFormat formatter = new SimpleDateFormat("HH:mm:ss");
        Date currentTime = new Date();
        String dateString = formatter.format(currentTime);

        if (writer != null) {
            while (packets.size() > 0) {
                writer.writePacket(packets.get(0));
                packets.remove(0);
            }
            writer.close();
            writer = null;
        
        }

        filename = dateString.replace(":", "-") + jpcap.toString() + ".dat";
        try {
            writer = JpcapWriter.openDumpFile(jpcap, option.filePathField + filename);
        } catch (Exception e) {
            e.printStackTrace();
        }


        if (jpcap != null) {

            isRun = true;
            frame.start();
            startCaptureThread();
        }

    }

    public void loadPacketsFromFile() {
        isRun = false;
        clear();

        int ret = JSnifferUI.chooser.showOpenDialog(frame);
        if (ret == JFileChooser.APPROVE_OPTION) {
            String path = JSnifferUI.chooser.getSelectedFile().getPath();

            try {
                if (jpcap != null) {
                    jpcap.close();
                }
                jpcap = JpcapCaptor.openFile(path);
            } catch (java.io.IOException e) {
                JOptionPane.showMessageDialog(
                        frame,
                        "Can't open file: " + path);
                e.printStackTrace();
                return;
            }

            frame.start();

            startCaptureThread();
        }
    }

    private void clear() {
        packets.clear();
        frame.clear();
        numOfPs = 0;
        sizeOfPs = 0;
        first = null;
        last = null;
        for (int i = 0; i < sframes.size(); i++) {
            ((JSnifferStatsFrame) sframes.get(i)).clear();
        }
    }

    public void saveToFile() {

        if (packets == null) {
            return;
        }

        try {
            if (writer == null) {
                writer = JpcapWriter.openDumpFile(jpcap, option.getFilePathField() + filename);
            }

            for (Packet p : packets) {
                writer.writePacket(p);
            }
            writer.close();
            writer = null;
      

        } catch (java.io.IOException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(
                    frame,
                    "Can't save file: " + option.getFilePathField() + jpcap.toString());
        }

    }

    public void stopCapture() {
        //if(writerisStart) writer.close();
        stopCaptureThread();
    }

    public void restartCapture() {
        restartWriter();
        restartCaptureThread();
    }

    public void saveIfNot() {
        if (isRun && writer != null) {
            int ret =
                    JOptionPane.showConfirmDialog(
                    null,
                    "Save this data?",
                    "Save this data?",
                    JOptionPane.YES_NO_OPTION);
            if (ret == JOptionPane.YES_OPTION) {
                saveToFile();
            }
        }
    }
    List<JSnifferStatsFrame> sframes = new ArrayList<JSnifferStatsFrame>();

    public void addCumulativeStatFrame(JSnifferStatBsc taker) {
        sframes.add(JSnifferStatcsFrame.openWindow(packets, taker.newInstance()));
    }

    public void closeAllWindows() {
        for (int i = 0; i < sframes.size(); i++) {
            ((JSnifferStatsFrame) sframes.get(i)).dispose();
        }
    }

    private void startCaptureThread() {
        if (captureThread != null) {
            return;
        }




        captureThread = new Thread(new Runnable() {

            public void run() {
                while (captureThread != null) {
                    if (jpcap.processPacket(1, handler) == 0 && !isRun) {
                        stopCaptureThread();
                    }
                    Thread.yield();
                }

                jpcap.breakLoop();
                frame.stop();
            }
        });

        frame.startTimer();
        for (int i = 0; i < sframes.size(); i++) {
            ((JSnifferStatsFrame) sframes.get(i)).startUpdating();
        }
        captureThread.start();
    }

    private void restartCaptureThread() {


        try {
            jpcap = JpcapCaptor.openDevice(option.getTheinterface(), option.getMaxlength(), option.isPromiscuous(), 50);
        } catch (Exception e) {
            e.printStackTrace();
        }
        clear();

        if (jpcap != null) {

            isRun = true;
            frame.start();

            startCaptureThread();
        }
    }

    void stopCaptureThread() {
        isRun = false;
        captureThread = null;
        frame.stopTimer();
        for (int i = 0; i < sframes.size(); i++) {
            ((JSnifferStatsFrame) sframes.get(i)).stopUpdating();
        }
    }
    private ExecutorService threadpool = Executors.newFixedThreadPool(10);
    public static final Map<InetAddress, String> hostnameCache = new HashMap<InetAddress, String>();
    private PacketReceiver handler = new PacketReceiver() {

        public void receivePacket(final Packet packet) {
            packets.add(packet);
            while (packets.size() > SAVE_NUMBER) {

                writer.writePacket(packet);
                packets.remove(0);

            }
            if (!sframes.isEmpty()) {
                for (int i = 0; i < sframes.size(); i++) {
                    ((JSnifferStatsFrame) sframes.get(i)).addPacket(packet);
                }
            }

            if (first == null) {
                first = new Date(packet.sec * 1000 + packet.usec / 1000);
            }
            last = new Date(packet.sec * 1000 + packet.usec / 1000);

            numOfPs++;
            sizeOfPs += packet.len;

            if (packet instanceof IPPacket) {
                threadpool.execute(new Runnable() {

                    public void run() {
                        IPPacket ip = (IPPacket) packet;
                        if (!hostnameCache.containsKey(ip.src_ip)) {
                            hostnameCache.put(ip.src_ip, ip.src_ip.getHostName());
                        }
                        if (!hostnameCache.containsKey(ip.dst_ip)) {
                            hostnameCache.put(ip.dst_ip, ip.dst_ip.getHostName());
                        }
                    }
                });
            }
        }
    };
}
