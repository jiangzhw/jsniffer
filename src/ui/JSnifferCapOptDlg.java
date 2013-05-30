package ui;

import jpcap.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferCapOptDlg extends JDialog implements ActionListener {

    static JSnifferOpt option = null;
    NetworkInterface[] interfaces;
    private JComboBox networkInterface;
    private JComboBox StopSize;
    private JTextField filterField;
    private JTextField caplenField;
    private JTextField filePathField;
    private JTextField stopNumSize;
    private JTextField stopPacketSize;
    private JCheckBox promiscuous;
    private JCheckBox limitlength;
    private JCheckBox StopControlSize;
    private JCheckBox StopControlPacket;

    public JSnifferCapOptDlg(JFrame parent) {
        super(parent, "ѡ��", true);
        option = ((JSnifferFrame) parent).jpcap.getOptions();
        if (option == null) {
            option = new JSnifferOpt();
        }
        interfaces = JpcapCaptor.getDeviceList();
        if (interfaces == null) {
            JOptionPane.showMessageDialog(parent, "����δ�ҵ���");
            dispose();
            return;
        } else {
            String[] names = new String[interfaces.length];
            for (int i = 0; i < names.length; i++) {
                if (interfaces[i].description != null) {
                    names[i] = interfaces[i].description.replace(" ", "");
                } else {
                    names[i] = interfaces[i].name;
                }
            }
            networkInterface = new JComboBox(names);

        }

        JPanel CapturePane = new JPanel(new GridLayout(5, 1));

        //ѡ������
        JPanel interfacePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        interfacePanel.add(new JLabel("����:"));
        interfacePanel.add(networkInterface);
        CapturePane.add(interfacePanel);

        //ѡ��ץ��ģʽ
        JPanel promisPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        promiscuous = new JCheckBox("�Ի���ģʽץ��");
        promiscuous.setSelected(true);
        promisPane.add(promiscuous);
        CapturePane.add(promisPane);

        //ץ����������
        JPanel limitPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        limitlength = new JCheckBox("����ÿ��ץ���ֽ���Ϊ:");
        limitlength.setSelected(false);
        limitlength.addActionListener(this);
        limitPane.add(limitlength);
        caplenField = new JTextField(20);
        limitPane.add(caplenField);
        CapturePane.add(limitPane);


        //����������
        filterField = new JTextField(50);
        JPanel filterPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filterPane.add(new JLabel("������:"));
        filterPane.add(filterField);
        CapturePane.add(filterPane);
        CapturePane.setBorder(BorderFactory.createTitledBorder("ץ��ѡ��"));

        //ץ���ļ�����λ��
        JPanel CaptureFilePane = new JPanel(new GridLayout(1, 1));
        JPanel CaptureFileUpPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        CaptureFileUpPane.add(new JLabel("�ļ�·��:"));
        filePathField = new JTextField(50);
        filePathField.setText("C:\\");
        filePathField.setEditable(false);
        CaptureFileUpPane.add(filePathField);
        CaptureFilePane.add(CaptureFileUpPane);
        CaptureFilePane.setBorder(BorderFactory.createTitledBorder("ץ���ļ�"));

        //ץ����ʱ����
       JPanel CaptureStopPane = new JPanel(new GridLayout(2, 1));
        JPanel CaptureStopUpPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        StopControlPacket = new JCheckBox("ֹͣץ����:");
        StopControlPacket.addActionListener(this);
        StopControlPacket.setSelected(false);
        stopPacketSize = new JTextField(5);
        CaptureStopUpPane.add(StopControlPacket);
        CaptureStopUpPane.add(stopPacketSize);
        CaptureStopUpPane.add(new JLabel(" ��֮��"));
        CaptureStopPane.add(CaptureStopUpPane);
        JPanel CaptureStopDownPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        StopControlSize = new JCheckBox("ֹͣץ����:");
        StopControlSize.addActionListener(this);
        CaptureStopDownPane.add(StopControlSize);
        stopNumSize = new JTextField(5);
        CaptureStopDownPane.add(stopNumSize);
        String sizes[] = {"KB", "MB", "GB"};
        StopSize = new JComboBox(sizes);
        CaptureStopDownPane.add(StopSize);
        CaptureStopPane.add(CaptureStopDownPane);
        CaptureStopPane.setBorder(BorderFactory.createTitledBorder("ֹͣץ��"));

        JPanel buttonPane = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okButton = new JButton("OK");
        okButton.setActionCommand("OK");
        okButton.addActionListener(this);
        if (((JSnifferFrame) parent).jpcap.isRun) {
            okButton.setEnabled(false);
        }
        JButton cancelButton = new JButton("Cancel");
        cancelButton.setActionCommand("Cancel");
        cancelButton.addActionListener(this);
        buttonPane.add(okButton);
        buttonPane.add(cancelButton);
        JPanel panelTemp = new JPanel(new GridLayout(2, 1));
        panelTemp.add(CaptureFilePane);
       panelTemp.add(CaptureStopPane);
        getContentPane().add(CapturePane, BorderLayout.NORTH);
        getContentPane().add(panelTemp, BorderLayout.CENTER);
        getContentPane().add(buttonPane, BorderLayout.SOUTH);
        loadStatus();
        this.setResizable(false);
        pack();

        setLocation(parent.getLocation().x + 100, parent.getLocation().y + 100);
    }

    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        Object source = e.getSource();

       if (source.equals(StopControlSize)) {
            if (StopControlSize.isSelected()) {
                StopSize.setEditable(true);
                stopNumSize.setEditable(true);
            } else {
                StopSize.setEditable(false);
                stopNumSize.setEditable(false);
            }
        }

        if (source.equals(StopControlPacket)) {
            if (StopControlPacket.isSelected()) {
                stopPacketSize.setEditable(true);
                StopSize.setEditable(true);
            } else {
                stopPacketSize.setEditable(false);
                StopSize.setEditable(false);
            }
        }

        if (cmd.equals("OK")) {
            try {

               if (caplenField.getText() != null && caplenField.getText().trim().length() > 0) {
                    if (isNumeric(caplenField.getText())) {
                        if (Integer.parseInt(caplenField.getText()) < 68) {
                            JOptionPane.showMessageDialog(null, "����Ӧ����68��");
                            return;
                        }
                        option.setMaxlength(Integer.parseInt(caplenField.getText()));
                    } else {
                        JOptionPane.showMessageDialog(null, "����ӦΪ���֣�");
                        return;
                    }
                } else {
                    option.setMaxlength(2000);
                }


               if (StopControlSize.isSelected()) {
                    if (stopNumSize.getText() != null && stopNumSize.getText().trim().length() > 0 && isNumeric(stopNumSize.getText())) {
                        option.setStopNumSize(Integer.parseInt(stopNumSize.getText()));
                        option.setStopSize(StopSize.getSelectedIndex());
                    } else {
                        JOptionPane.showMessageDialog(null, "�������֣�");
                        return;
                    }
                } else {
                    option.setSaveNumSize(-1);
                    option.setSaveSize(-1);
                }

                if (StopControlPacket.isSelected()) {
                    if (stopPacketSize.getText() != null && stopPacketSize.getText().trim().length() > 0 && isNumeric(stopPacketSize.getText())) {
                        option.setStopPacketSize(Integer.parseInt(stopPacketSize.getText()));
                    } else {
                        JOptionPane.showMessageDialog(null, "�������֣�");
                        return;
                    }
                } else {
                    option.setStopPacketSize(-1);

                }

                option.setTheinterface(interfaces[networkInterface.getSelectedIndex()]);

                if (filterField.getText() != null && filterField.getText().trim().length() > 0) {
                    option.setFilterField(filterField.getText());
                } else {
                    option.setFilterField(null);

                }

                option.setPromiscuous(promiscuous.isSelected());


            } catch (NumberFormatException nfe) {
                JOptionPane.showMessageDialog(null, "ֵ���ǺϷ���������");
            } /*catch (Exception ept){
                System.out.println(ept);
            }*/
            finally {
                dispose();
            }
        } else if (cmd.equals("Cancel")) {
            dispose();
        }


    }

    public void loadStatus() {
        if (option.getFilterField() != null) {
            filterField.setText(option.getFilterField());
        }

        if (option.getMaxlength() != 2000) {
            limitlength.setSelected(true);
            caplenField.setText(Integer.toString(option.getMaxlength()));
        }

        if (option.getTheinterface() != null) {
            for (int i = 0; i < interfaces.length; i++) {
                if (option.getTheinterface().equals(interfaces[i])) {
                    networkInterface.setSelectedIndex(i);
                }

            }
        }

        if (option.getStopNumSize() != -1) {
            StopControlSize.setSelected(true);
            stopNumSize.setText(String.valueOf(option.getStopNumSize()));
            StopSize.setSelectedIndex(option.getStopSize());
        }

        if (option.getStopPacketSize() != -1) {
            StopControlPacket.setSelected(true);
            stopPacketSize.setText(String.valueOf(option.getStopPacketSize()));
        }

    }

    public boolean isNumeric(String s) {
        if ((s != null) && (s != "")) {
            return s.matches("^[0-9]*$");
        } else {
            return false;
        }
    }

    public static JSnifferOpt getJpcap(JFrame parent) {
        new JSnifferCapOptDlg(parent).setVisible(true);
        return option;
    }
}
