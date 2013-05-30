package ui;

import statistics.JSnifferStatBsc;
import jpcap.packet.*;
import java.awt.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferStatcsFrame extends JSnifferStatsFrame implements ListSelectionListener {

    JTable table;
    TableModel model = null;
    JSnifferStatBsc member;
    int statType = 0;

    public static JSnifferStatcsFrame openWindow(java.util.List<Packet> packets, JSnifferStatBsc staker) {
        JSnifferStatcsFrame frame = new JSnifferStatcsFrame(packets, staker);
        frame.setVisible(true);
        return frame;
    }

    JSnifferStatcsFrame(java.util.List<Packet> packets, JSnifferStatBsc staker) {
        super(staker.getName());
        this.member = staker;
        staker.take(packets);

        getContentPane().setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

        model = new TableModel();
        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JTableHeader header = table.getTableHeader();
        Dimension dim = header.getPreferredSize();
        dim.height = 20;
        header.setPreferredSize(dim);
        JScrollPane tablePane = new JScrollPane(table);
        dim = table.getMinimumSize();
        dim.height += 25;
        tablePane.setPreferredSize(dim);

        if (staker.getLabels().length > 1) {
            getContentPane().add(tablePane);
            table.getSelectionModel().addListSelectionListener(this);
        } else {
            getContentPane().add(tablePane);
        }

        setSize(500, 120);
    }

    void fireUpdate() {
        int sel = table.getSelectedRow();
        if (model != null) {
            model.update();
        }
        if (sel >= 0) {
            table.setRowSelectionInterval(sel, sel);
        }
        repaint();
    }

    public void addPacket(Packet p) {
        member.addPacket(p);
    }

    public void clear() {
        member.clear();
        if (model != null) {
            model.update();
        }
    }

    public void valueChanged(ListSelectionEvent evt) {
        if (evt.getValueIsAdjusting()) {
            return;
        }
        ListSelectionModel lsm = (ListSelectionModel) evt.getSource();
        if (lsm.isSelectionEmpty()) {
            statType = 0;
        } else {
            statType = lsm.getMinSelectionIndex();
        }
    }

    class TableModel extends AbstractTableModel {

        String[] labels;
        Object[][] values;

        TableModel() {
            labels = new String[member.getLabels().length + 1];
            labels[0] = new String();
            System.arraycopy(member.getLabels(), 0, labels, 1, member.getLabels().length);

            String[] types = member.getStatTypes();
            values = new Object[types.length][member.getLabels().length + 1];
            for (int i = 0; i < values.length; i++) {
                values[i][0] = types[i];
                long[] v = member.getValues(i);
                for (int j = 0; j < v.length; j++) {
                    values[i][j + 1] = new Long(v[j]);
                }
            }
        }

        @Override
        public String getColumnName(int c) {
            return labels[c];
        }

        public int getColumnCount() {
            return labels.length;
        }

        public int getRowCount() {
            return values.length;
        }

        public Object getValueAt(int row, int column) {
            return values[row][column];
        }

        void update() {
            String[] types = member.getStatTypes();
            values = new Object[types.length][member.getLabels().length + 1];
            for (int i = 0; i < values.length; i++) {
                values[i][0] = types[i];
                long[] v = member.getValues(i);
                for (int j = 0; j < v.length; j++) {
                    values[i][j + 1] = new Long(v[j]);
                }
            }
            fireTableDataChanged();
        }
    }
}
