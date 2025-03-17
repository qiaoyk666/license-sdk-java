package license;

public class InitResp {
	private String msg;
	private Boolean result;
	
	public InitResp(String msg, Boolean result) {
		super();
		this.msg = msg;
		this.result = result;
	}
	public String getMsg() {
		return msg;
	}
	public void setMsg(String msg) {
		this.msg = msg;
	}
	public Boolean getResult() {
		return result;
	}
	public void setResult(Boolean result) {
		this.result = result;
	}
	
	
}