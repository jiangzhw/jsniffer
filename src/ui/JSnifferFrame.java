package ui;

import statistics.JSnifferStatBsc;
import statistics.JSnifferStat;
import analyser.JSnifferCaptor;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferFrame extends JFrame implements ActionListener {

    private JMenu statMenu;
    private JMenuItem openMenu;
    private JMenuItem saveMenu;
    private JMenuItem startMenu;
    private JMenuItem stopMenu;
    private JMenuItem restartMenu;
    private JMenuItem optionMenu;
    private JMenuItem helpMenu;
    public JSnifferDwnPanel tablePane;
    public JSnifferCaptor jpcap;
    public JPanel statisPane;
    static int[] SIZE = {1024, 1024 * 1024, 1024 * 1024 * 1024};

         public void setStartMenu(){
            startMenu.setEnabled(false);
        }

    public static JSnifferFrame openNewWindow(JSnifferCaptor jpcap) {
        JSnifferFrame f = new JSnifferFrame(jpcap);
        f.setVisible(true);
        f.setSize(900, 600);
        f.setMinimumSize(new Dimension(700, 550));
        return f;
    }

    public JSnifferFrame(JSnifferCaptor captor) {
        this.jpcap = captor;
        tablePane = new JSnifferDwnPanel(captor);
        captor.setFrame(this);

        setTitle("JSniffer");


        JMenuBar menuBar = new JMenuBar();
        setJMenuBar(menuBar);


        //文件菜单
        JMenu menu = new JMenu("文件");
        menuBar.add(menu);
        openMenu = new JMenuItem("打开");
        openMenu.setIcon(new ImageIcon(Frame.class.getResource("/ui/image/open.gif")));
        openMenu.setActionCommand("Open");
        openMenu.addActionListener(this);
        menu.add(openMenu);
        saveMenu = new JMenuItem("保存");
        saveMenu.setIcon(new ImageIcon(Frame.class.getResource("/ui/image/save.gif")));
        saveMenu.setActionCommand("Save");
        saveMenu.addActionListener(this);
        saveMenu.setEnabled(false);
        menu.add(saveMenu);
        JMenuItem item = new JMenuItem("退出");
        item.setActionCommand("Exit");
        item.addActionListener(this);
        menu.add(item);

        //捕捉菜单
        menu = new JMenu("捕捉");
        menuBar.add(menu);
        startMenu = new JMenuItem("开始");
        startMenu.setIcon(new ImageIcon(Frame.class.getResource("/ui/image/capture.gif")));
        startMenu.setActionCommand("Start");
        startMenu.addActionListener(this);
        
        /*if(GlobalVar.capcount>0){
            System.out.println(GlobalVar.capcount);
           startMenu.setEnabled(false);
        }*/
       

        menu.add(startMenu);
        restartMenu = new JMenuItem("重启");
        restartMenu.setIcon(new ImageIcon(Frame.class.getResource("/ui/image/capture.gif")));
        restartMenu.setActionCommand("Restart");
        restartMenu.addActionListener(this);
        restartMenu.setEnabled(false);
        menu.add(restartMenu);
        optionMenu = new JMenuItem("选项");
        optionMenu.setIcon(new ImageIcon(Frame.class.getResource("/ui/image/nic.gif")));
        optionMenu.setActionCommand("Option");
        optionMenu.addActionListener(this);
        menu.add(optionMenu);
        stopMenu = new JMenuItem("停止");
        stopMenu.setIcon(new ImageIcon(Frame.class.getResource("/ui/image/stop.gif")));
        stopMenu.setActionCommand("Stop");
        stopMenu.addActionListener(this);
        stopMenu.setEnabled(false);
        menu.add(stopMenu);

        //统计菜单
        statMenu = new JMenu("统计");
        java.util.List<JSnifferStatBsc> stakers = JSnifferStat.getStatisticsTakers();
        for (int i = 0; i < stakers.size(); i++) {
            item = new JMenuItem(stakers.get(i).getName());
            item.setIcon(new ImageIcon(Frame.class.getResource("/ui/image/stat.gif")));
            item.setActionCommand("CUMSTAT" + i);
            item.addActionListener(this);
            statMenu.add(item);
        }
        menuBar.add(statMenu);

        //帮助菜单
        helpMenu = new JMenu("帮助");
        menuBar.add(helpMenu);
        item = new JMenuItem("关于JSniffer");
        item.setActionCommand("Help");
        item.addActionListener(this);
        helpMenu.add(item);

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(tablePane, BorderLayout.CENTER);

        addWindowListener(new WindowAdapter() {

            @Override
            public void windowClosing(WindowEvent evt) {
                JSnifferUI.closeWindow((JSnifferFrame) evt.getSource());
            }
        });

    }


    public static final String DLG_HLP = ""
			+ "1.一个基于Jpcap的简单网络嗅探器JSnifferV0.05;  \r\n"
			+ "2.运行程序前请确保已正常安装Winpcap4.x;        \r\n"
			+ "3.请把Jpap.dll复制到系统的path如system32目录下;\r\n"
			+ "4.By jiangzhw2008@yeah.net                    \r\n";

    public void actionPerformed(ActionEvent evt) {
        String cmd = evt.getActionCommand();
        if (cmd.equals("Open")) {
            jpcap.loadPacketsFromFile();
        } else if (cmd.equals("Save")) {
            jpcap.saveToFile();
            saveMenu.setEnabled(false);

        } else if (cmd.equals("Exit")) {
            System.exit(0);
        } else if (cmd.equals("Start")) {
            jpcap.capturePackets();
            startMenu.setEnabled(false);
        } else if (cmd.equals("Option") && !jpcap.isRun) {
            jpcap.capturePackets();
        } else if (cmd.equals("Option") && jpcap.isRun) {
            JSnifferCapOptDlg.getJpcap(this);
        } else if (cmd.equals("Stop")) {
            jpcap.stopCapture();
        } else if (cmd.equals("Restart")) {
            jpcap.restartCapture();
        } else if (cmd.startsWith("CUMSTAT")) {
            int index = Integer.parseInt(cmd.substring(7));
            jpcap.addCumulativeStatFrame(JSnifferStat.getStatisticsTakerAt(index));
        } else if (cmd.equals("Help")) {
            JOptionPane.showMessageDialog(this, DLG_HLP);
        }

    }

    public void clear() {
        tablePane.clear();
    }

    public void startTimer() {
        timerUpdater.setRepeats(true);
        timerUpdater.start();
    }

    public void stopTimer() {
        timerUpdater.stop();
        timerUpdater.setRepeats(false);
        timerUpdater.start();
    }
    javax.swing.Timer timerUpdater = new javax.swing.Timer(500, new ActionListener() {

        public void actionPerformed(ActionEvent evt) {
            tablePane.fireTableChanged();
            if (jpcap.getOptions().stopPacketSize != -1) {
                if (jpcap.getOptions().stopPacketSize < jpcap.numOfPs) {
                    jpcap.stopCapture();
                }
            }
            if (jpcap.getOptions().getStopNumSize() != -1) {

                if (jpcap.getOptions().getStopNumSize() * SIZE[jpcap.getOptions().getStopSize()] < jpcap.sizeOfPs) {
                    jpcap.stopCapture();
                }
            }

            repaint();
        }
    });

    public void stop() {

        openMenu.setEnabled(true);
        saveMenu.setEnabled(true);
        startMenu.setEnabled(false);
        stopMenu.setEnabled(false);
        restartMenu.setEnabled(true);
        optionMenu.setEnabled(true);

    }

    public void start() {

        restartMenu.setEnabled(false);
        openMenu.setEnabled(false);
        startMenu.setEnabled(false);
        saveMenu.setEnabled(false);
        stopMenu.setEnabled(true);
        optionMenu.setEnabled(true);

    }


}
  
