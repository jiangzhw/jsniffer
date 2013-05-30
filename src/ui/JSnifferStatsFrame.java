package ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import jpcap.packet.*;
import javax.swing.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */

public abstract class JSnifferStatsFrame extends JFrame
{
	JSnifferStatsFrame(String title){
		super(title);
		
		TimerUpdater.start();
		addWindowListener(new java.awt.event.WindowAdapter(){
            @Override
			public void windowClosed(java.awt.event.WindowEvent evt){
				setVisible(false);
			}
		});
	}
	abstract void fireUpdate();
	public abstract void addPacket(Packet p);
	public abstract void clear();

	public void startUpdating(){
		TimerUpdater.setRepeats(true);
		TimerUpdater.start();
	}
	
	public void stopUpdating(){
		TimerUpdater.stop();
		TimerUpdater.setRepeats(false);
		TimerUpdater.start();
	}

	javax.swing.Timer TimerUpdater=new javax.swing.Timer(500,new ActionListener(){
		public void actionPerformed(ActionEvent evt){
			fireUpdate();
			repaint();
		}
	});

}
