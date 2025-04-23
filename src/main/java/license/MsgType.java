package license;

public enum MsgType {
	WsMsgTypePermissionTree(1),
    WsMsgTypeExpireWarning(2);

	int msgType;
	MsgType(int msgType) {
		this.msgType = msgType;
	}

	public int getMsgType() {
		return msgType;
	}
	
	public static MsgType fromValue(int value) {
		for (MsgType t: MsgType.values()) {
			if (t.getMsgType() == value) {
				return t;
			}
		}
        throw new IllegalArgumentException("No enum constant with value " + value);
	}
}