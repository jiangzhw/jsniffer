package ui;

import jpcap.NetworkInterface;

/**
 * @author jiangzhw2008@yeah.net
 *
 */

public class JSnifferOpt {
  
	public NetworkInterface theinterface=null;
	public int Maxlength=2000;
	public int SaveTime=-1;
	public int SaveSize=-1;
	public int StopTime=-1;
	public int StopSize=-1;
	public String filterField=null;
	public String filePathField="C:\\";
	public int saveNumTime=-1;
	public int saveNumSize=-1;
	public int stopNumTime=-1;
	public int stopNumSize=-1;
	public int stopPacketSize=-1;
	public boolean promiscuous=true;
	
	public JSnifferOpt(NetworkInterface theinterface,int Maxlength,int SaveTime,int SaveSize,int StopSize,int StopTime,String  filterField,String filePathField,int saveNumTime,
			int saveNumSize,int stopNumTime,int stopNumSize,int stopPacketSize,boolean promiscuous)
	{
		this.theinterface=theinterface;
		this.Maxlength=Maxlength;
		this.SaveTime=SaveTime;
		this.SaveSize=SaveSize;
		this.StopTime=StopTime;
		this.StopSize=StopSize;
		this.filterField=filterField;
		this.filePathField=filePathField;
		this.saveNumTime=saveNumTime;
		this.saveNumSize=saveNumSize;
		this.stopNumTime=stopNumTime;
		this.stopNumSize=stopNumSize;
		this.stopPacketSize=stopPacketSize;
		this.promiscuous=promiscuous;
	}

	public JSnifferOpt()
	{
		
	}
	
	public String getFilePathField() {
		return filePathField;
	}

	public void setFilePathField(String filePathField) {
		this.filePathField = filePathField;
	}

	public boolean isPromiscuous() {
		return promiscuous;
	}

	public void setPromiscuous(boolean promiscuous) {
		this.promiscuous = promiscuous;
	}

	public String getFilterField() {
		return filterField;
	}

	public void setFilterField(String filterField) {
		this.filterField = filterField;
	}

	public int getMaxlength() {
		return Maxlength;
	}

	public void setMaxlength(int maxlength) {
		Maxlength = maxlength;
	}

	public int getSaveNumSize() {
		return saveNumSize;
	}

	public void setSaveNumSize(int saveNumSize) {
		this.saveNumSize = saveNumSize;
	}

	public int getSaveNumTime() {
		return saveNumTime;
	}

	public void setSaveNumTime(int saveNumTime) {
		this.saveNumTime = saveNumTime;
	}

	public int getSaveSize() {
		return SaveSize;
	}

	public void setSaveSize(int saveSize) {
		SaveSize = saveSize;
	}

	public int getSaveTime() {
		return SaveTime;
	}

	public void setSaveTime(int saveTime) {
		SaveTime = saveTime;
	}

	public int getStopNumSize() {
		return stopNumSize;
	}

	public void setStopNumSize(int stopNumSize) {
		this.stopNumSize = stopNumSize;
	}

	public int getStopNumTime() {
		return stopNumTime;
	}

	public void setStopNumTime(int stopNumTime) {
		this.stopNumTime = stopNumTime;
	}

	public int getStopPacketSize() {
		return stopPacketSize;
	}

	public void setStopPacketSize(int stopPacketSize) {
		this.stopPacketSize = stopPacketSize;
	}

	public int getStopSize() {
		return StopSize;
	}

	public void setStopSize(int stopSize) {
		StopSize = stopSize;
	}

	public int getStopTime() {
		return StopTime;
	}

	public void setStopTime(int stopTime) {
		StopTime = stopTime;
	}

	public NetworkInterface getTheinterface() {
		return theinterface;
	}

	public void setTheinterface(NetworkInterface theinterface) {
		this.theinterface = theinterface;
	}
	
	
}
