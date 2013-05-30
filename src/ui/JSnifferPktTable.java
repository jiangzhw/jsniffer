package ui;

import javax.swing.*;
import javax.swing.table.*;
import java.util.*;
import java.awt.*;
import analyser.*;
import jpcap.packet.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
class JSnifferPktTable extends JComponent {

    JDTableModel model;
    Vector views = new Vector();
    JSnifferCaptor jpcap;
    static JSnifferPktDtls[] analyzers = {new JSnifferEthernetDtls(), new JSnifferIPv4Dtls(), new JSnifferIPv4Dtls(), new JSnifferPktInfo(), new JSnifferPktInfo(), new JSnifferEthernetDtls(), new JSnifferEthernetDtls()};
    static JSnifferARPDtl arp;
    static JSnifferIPDtl ip;
    static JSnifferEthernetDtl ether;

    JSnifferPktTable(JSnifferDwnPanel parent, JSnifferCaptor captor) {
        this.jpcap = captor;
        model = new JDTableModel();
        JTable table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(parent);
        JScrollPane tableView = new JScrollPane(table);
        arp = new JSnifferARPDtl();
        ip = new JSnifferIPDtl();
        ether = new JSnifferEthernetDtl();
        setLayout(new BorderLayout());
        add(tableView, BorderLayout.CENTER);
    }

    void fireTableChanged() {
        model.fireTableRowsInserted(jpcap.getPackets().size() - 1, jpcap.getPackets().size() - 1);
    }

    void clear() {
        model.fireTableStructureChanged();
        model.fireTableDataChanged();
    }

    String[] getTableViewStatus() {
        String[] status = new String[views.size()];

        for (int i = 0; i < status.length; i++) {
            TableView view = (TableView) views.elementAt(i);
            status[i] = view.analyzer.getProtocol() + ":" + view.valueName;
        }

        return status;
    }

    class TableView {

        JSnifferPktDtls analyzer;
        String valueName;

        TableView(JSnifferPktDtls analyzer, String name) {
            this.analyzer = analyzer;
            valueName = name;
        }
    }

    class JDTableModel extends AbstractTableModel {

        String[] names = {"编号", "捕获时间", "协议", "源址", "目的", "信息摘要", "大小"};

        public int getRowCount() {
            return jpcap.getPackets().size();
        }

        public int getColumnCount() {
            return names.length;
        }

        public JSnifferPktDtls getAnalyzer(int column) {
            return analyzers[column - 1];
        }

        public Object getValueAt(int row, int column) {
            if (jpcap.getPackets().size() <= row) {
                return "";
            }

            Packet packet = (Packet) (jpcap.getPackets().get(row));

            if (column == 0) {
                if (jpcap.numOfPs >= jpcap.SAVE_NUMBER) {
                    return new Integer((int) (jpcap.numOfPs - jpcap.SAVE_NUMBER) + row);
                } else {
                    return row;
                }
            }

            if (JSnifferARPDtl.isInstance(packet)) {
                arp.setPacket(packet);
                if (column == 1) {
                    return arp.getTime();
                } else if (column == 2) {
                    return arp.getProtocol();
                } else if (column == 3) {
                    return arp.getSenderHardwareAddress();
                } else if (column == 4) {
                    return arp.getTargetHardwareAddress();
                } else if (column == 5) {
                    return arp.getInfo();
                } else if (column == 6) {
                    return arp.getCapturedLength();
                } else {
                    return null;
                }

            } else if (JSnifferIPDtl.isInstance(packet)) {
                ip.setPacket(packet);
                if (column == 1) {
                    return ip.getTime();
                } else if (column == 2) {
                    return ip.getPrototype();
                } else if (column == 3) {
                    return ip.getSourceIPaddress().getHostAddress();
                } else if (column == 4) {
                    return ip.getDestinationIPaddress().getHostAddress();
                } else if (column == 5) {
                    return ip.getInfo();
                } else if (column == 6) {
                    return ip.getCapturedLength();
                } else {
                    return null;
                }
            } else {
                ether.setPacket(packet);
                if (column == 1) {
                    return ether.getTime();
                } else if (column == 2) {
                    return "Ethernet Frame";
                } else if (column == 3) {
                    return ether.getSourceHardwareAddress();
                } else if (column == 4) {
                    return ether.getDestinationHardwareAddress();
                } else if (column == 5) {
                    return "UNKNOW";
                } else if (column == 6) {
                    return ether.getCapturedLength();
                } else {
                    return null;
                }
            }
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }

       @Override
        public String getColumnName(int column) {
            if (column == 0) {
                return "编号";
            }

            return names[column];
        }
    }
}
