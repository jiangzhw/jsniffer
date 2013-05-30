package ui;

import analyser.JSnifferPktDataDtl;
import analyser.JSnifferCaptor;
import java.awt.*;
import javax.swing.*;
import javax.swing.event.*;
import analyser.JSnifferPktDtls;
import java.util.List;
import jpcap.packet.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
class JSnifferDwnPanel extends JPanel implements ListSelectionListener {

    JSnifferPktTable table;
    JSnifferPktTree tree;
    JSnifferPktDataDtl text;
    JSnifferCaptor captor;
    List<JSnifferPktDtls> analyzers;

    JSnifferDwnPanel(JSnifferCaptor captor) {
        this.captor = captor;
        table = new JSnifferPktTable(this, captor);
        tree = new JSnifferPktTree();
        text = new JSnifferPktDataDtl();

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JSplitPane splitPane2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(table);
        splitPane2.setTopComponent(tree);
        splitPane2.setBottomComponent(new JScrollPane(text));
        splitPane.setBottomComponent(splitPane2);
        splitPane.setDividerLocation(260);
        splitPane2.setDividerLocation(100);

        analyzers = JSnifferPktAdd.getAnalyzers();

        setLayout(new BorderLayout());
        add(splitPane, BorderLayout.CENTER);
        setSize(400, 200);
    }

    void fireTableChanged() {
        table.fireTableChanged();
    }

    void clear() {
        table.clear();
    }

    public void valueChanged(ListSelectionEvent evt) {
        if (evt.getValueIsAdjusting()) {
            return;
        }

        int index = ((ListSelectionModel) evt.getSource()).getMinSelectionIndex();
        if (index >= 0) {
            Packet p = (Packet) captor.getPackets().get(index);
            tree.analyzePacket(p);
            text.packetData(p);
        }
    }
}
