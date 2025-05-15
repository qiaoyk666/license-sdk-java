package license;

public class HeartbeatMsg {
	private MsgType msgType;
	private String msg;
	
	public MsgType getMsgType() {
		return msgType;
	}
	public void setMsgType(MsgType msgType) {
		this.msgType = msgType;
	}
	public String getMsg() {
		return msg;
	}
	public void setMsg(String msg) {
		this.msg = msg;
	}
	public HeartbeatMsg(MsgType msgType, String msg) {
		super();
		this.msgType = msgType;
		this.msg = msg;
	}
	
	
}
