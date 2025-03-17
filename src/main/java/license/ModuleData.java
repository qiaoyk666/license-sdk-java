package license;

import java.util.ArrayList;

public class ModuleData {
	private String key;
	private String name;
	private int issuedTime;
	private int expireTime;
	private String extra;
	private ArrayList<ModuleData> childFuncs;
	
	public String getKey() {
		return key;
	}
	public void setKey(String key) {
		this.key = key;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getIssuedTime() {
		return issuedTime;
	}
	public void setIssuedTime(int issuedTime) {
		this.issuedTime = issuedTime;
	}
	public int getExpireTime() {
		return expireTime;
	}
	public void setExpireTime(int expireTime) {
		this.expireTime = expireTime;
	}
	public String getExtra() {
		return extra;
	}
	public void setExtra(String extra) {
		this.extra = extra;
	}
	public ArrayList<ModuleData> getChildFuncs() {
		return childFuncs;
	}
	public void setChildFuncs(ArrayList<ModuleData> childFuncs) {
		this.childFuncs = childFuncs;
	}
}
