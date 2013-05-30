package ui;

import statistics.JSnifferStat;
import analyser.JSnifferCaptor;
import java.util.ArrayList;
import javax.swing.JOptionPane;
import javax.swing.UIManager;
import javax.swing.plaf.metal.MetalLookAndFeel;
import javax.swing.plaf.metal.OceanTheme;
import jpcap.NetworkInterface;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferUI {

    public static javax.swing.JFileChooser chooser;
    private static ArrayList<JSnifferFrame> frames = new ArrayList<JSnifferFrame>();

    public static void main(String[] args) throws Exception {
        //界面美观设置
        String lookandfeel = "javax.swing.plaf.metal.MetalLookAndFeel";
        UIManager.setLookAndFeel(lookandfeel);
        MetalLookAndFeel.setCurrentTheme(new OceanTheme());
        chooser = new javax.swing.JFileChooser();
        try {
            Class.forName("jpcap.JpcapCaptor");
            NetworkInterface[] devices = jpcap.JpcapCaptor.getDeviceList();
            if (devices.length == 0) {
                JOptionPane.showMessageDialog(null, "未找到网卡！\n你可能需要拥有管理员身份！",
                        "警告", JOptionPane.WARNING_MESSAGE);
            }
        } catch (ClassNotFoundException e) {
            JOptionPane.showMessageDialog(null, "未找到Jpcap,请按照帮助说明安装Jpacp！",
                    "错误", JOptionPane.ERROR_MESSAGE);
            System.exit(-1);
        } catch (UnsatisfiedLinkError e) {
            JOptionPane.showMessageDialog(null, "未找到Winpcap.\n 请安装Winpcap!",
                    "错误", JOptionPane.ERROR_MESSAGE);
            System.exit(-1);
        }


        JSnifferPktAdd.loadDefaultAnalyzer();
        JSnifferStat.loadStatisticsTaker();

        openNewWindow();
    }

    public static void openNewWindow() {
        JSnifferCaptor jpcap = new JSnifferCaptor();
        frames.add(JSnifferFrame.openNewWindow(jpcap));
    }

    public static void closeWindow(JSnifferFrame frame) {
        frame.jpcap.stopCapture();
        frame.jpcap.saveIfNot();
        frame.jpcap.closeAllWindows();
        frames.remove(frame);
        frame.dispose();
        if (frames.isEmpty()) {
            System.exit(0);
        }
    }

    protected void finalize() throws Throwable {
    }
}
