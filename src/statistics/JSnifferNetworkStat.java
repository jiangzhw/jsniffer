package statistics;

import ui.*;
import jpcap.packet.*;
import java.util.*;
import analyser.JSnifferPktDtls;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferNetworkStat extends JSnifferStatBsc {

    List<JSnifferPktDtls> analyzers;
    long[] numOfPs;
    long totalPs;
    long[] sizeOfPs;
    long totalSize;
    String[] labels;
    static final String[] types = {"包总数量", "数量(%)", "总大小", "大小(%)"};

    public JSnifferNetworkStat() {
        analyzers = JSnifferPktAdd.getAnalyzersOf(JSnifferPktDtls.NETWORK_LAYER);
        numOfPs = new long[analyzers.size() + 1];
        sizeOfPs = new long[analyzers.size() + 1];

        labels = new String[analyzers.size() + 1];
        for (int i = 0; i < analyzers.size(); i++) {
            labels[i] = analyzers.get(i).getProtocol();
        }
        labels[analyzers.size()] = "other";
    }

    public String getName() {
        return "网络层";
    }

    public void take(List<Packet> packets) {
        for (int i = 0; i < packets.size(); i++) {
            Packet p = (Packet) packets.get(i);
            totalPs++;
            totalSize += p.len;

            boolean flag = false;
            for (int j = 0; j < analyzers.size(); j++) {
                if (analyzers.get(j).isInstance(p)) {
                    numOfPs[j]++;
                    totalPs++;
                    sizeOfPs[j] += p.len;
                    flag = true;
                    break;
                }
            }
            if (!flag) {
                numOfPs[numOfPs.length - 1]++;
                sizeOfPs[sizeOfPs.length - 1] += p.len;
            }
        }
    }

    public void addPacket(Packet p) {
        boolean flag = false;
        totalPs++;
        totalSize += p.len;
        for (int j = 0; j < analyzers.size(); j++) {
            if (analyzers.get(j).isInstance(p)) {
                numOfPs[j]++;
                sizeOfPs[j] += p.len;
                flag = true;
                break;
            }
        }
        if (!flag) {
            numOfPs[numOfPs.length - 1]++;
            sizeOfPs[sizeOfPs.length - 1] += p.len;
        }
    }

    public String[] getLabels() {
        return labels;
    }

    public String[] getStatTypes() {
        return types;
    }

    public long[] getValues(int index) {
        switch (index) {
            case 0:
                if (numOfPs == null) {
                    return new long[0];
                }
                return numOfPs;
            case 1:
                long[] percents = new long[numOfPs.length];
                if (totalPs == 0) {
                    return percents;
                }
                for (int i = 0; i < numOfPs.length; i++) {
                    percents[i] = numOfPs[i] * 100 / totalPs;
                }
                return percents;
            case 2:
                if (sizeOfPs == null) {
                    return new long[0];
                }
                return sizeOfPs;
            case 3:
                long[] percents2 = new long[sizeOfPs.length];
                if (totalSize == 0) {
                    return percents2;
                }
                for (int i = 0; i < sizeOfPs.length; i++) {
                    percents2[i] = sizeOfPs[i] * 100 / totalSize;
                }
                return percents2;
            default:
                return null;
        }
    }

    public void clear() {
        numOfPs = new long[analyzers.size() + 1];
        sizeOfPs = new long[analyzers.size() + 1];
        totalPs = 0;
        totalSize = 0;
    }
}
