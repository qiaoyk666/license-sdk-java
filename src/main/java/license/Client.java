package license;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.java_websocket.WebSocket;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import org.bouncycastle.crypto.Signer;
import com.alibaba.fastjson2.JSON;


public class Client {
	//	服务地址
	private String endpoint;
	//	标品id
	private String prodKey;
	// 客户端公钥
	private String publicKey;
	ModuleData module;
	private String _public_key = "9703919fcd22d32a13bb00fba33a2dd0d35746a597f7c5a4843c567c3482c204";
	public Client(String endpoint, String prodKey) {
		this.endpoint = endpoint;
		this.prodKey = prodKey;
	}
	
	public InitResp init() {	
		InitResp initResp = new InitResp("", false);
		
		// 1. 获取公钥
		String resp = this.httpRequest("http://"+this.endpoint+"/pubkey?prodkey="+this.prodKey);
		PubkeyResp pubResp = JSON.parseObject(resp, PubkeyResp.class);
		if (pubResp.getCode() != 200) {
			String msg = "failed to get auth info: " + pubResp.getMsg();
			initResp.setMsg(msg);
			return initResp;
		}
		
		// 2. AES解密返回的数据
		PubkeyData pubkeyData;
		try {
			pubkeyData = this.aes_ECB_decrypt(pubResp.getData(), _public_key.substring(0, 32));
			if (pubkeyData.getProdKey() != this.prodKey) {
				String msg = "prodkey not match";
				initResp.setMsg(msg);
				return initResp;
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			String msg = "aes decrypt data error: " + e;
			initResp.setMsg(msg);
			return initResp;
		}
		
		this.publicKey = pubkeyData.getPublicKey();
		
		// 3. 获取权限树
		String moduleRespStr = this.httpRequest("http://"+this.endpoint+"/modules?prodkey="+this.prodKey);
		ModuleResp moduleResp = JSON.parseObject(moduleRespStr, ModuleResp.class);
		
		if (moduleResp.getCode() != 200) {
			String msg = "failed to get modules: " + moduleResp.getMsg();
			initResp.setMsg(msg);
			return initResp;
		}
		
		// 4. 校验权限树签名
		SignData signData = JSON.parseObject(moduleResp.getData(), SignData.class);
		boolean veryfyResult = this.verifyModuleMsg(signData);
		if (!veryfyResult) {
			initResp.setMsg("sign validation is not approved");
			return initResp;
		}
		

		Base64.Decoder decoder = Base64.getDecoder();
		ModuleData moduleData = JSON.parseObject(new String(decoder.decode(signData.getMsg())), ModuleData.class);
		this.module = moduleData;
		initResp.setResult(true);
		
		// 5. 开启websocket监听
		this.handleWebSocket();
		
		return initResp;
	}
	
	private void handleWebSocket() {
		try {
        	LicenseWebSocketClient wsClient = new LicenseWebSocketClient(new URI("ws://" + this.endpoint + "/ws?prodkey=" + this.prodKey), this);
        	wsClient.connect();
            while (!wsClient.getReadyState().equals(WebSocket.READYSTATE.OPEN)) {
                System.out.println("连接中。。。");
                Thread.sleep(1000);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	public boolean verifyModuleMsg(SignData signData) {
		return this.verifySign(this.publicKey, signData.getSign(), signData.getMsg());
	}
	
	private boolean verifySign(String pubkey, String sign, String msg) {
		// 将十六进制字符串转换为字节数组
		Base64.Decoder decoder = Base64.getDecoder();
		
        byte[] publicKeyBytes = new BigInteger(pubkey, 16).toByteArray();   
        byte[] signatureBytes = decoder.decode(sign);
        byte[] messageBytes = decoder.decode(msg);
        
        // 创建Ed25519公钥参数
        Ed25519PublicKeyParameters publicKeyParams = new Ed25519PublicKeyParameters(publicKeyBytes, 0);

        // 创建签名验证器
        Signer signer = new Ed25519Signer();
        signer.init(false, publicKeyParams);
        signer.update(messageBytes, 0, messageBytes.length);

        // 验证签名
        boolean isValid = signer.verifySignature(signatureBytes);
        System.out.println("签名是否有效: " + isValid);
        return isValid;
	}
	
	private PubkeyData aes_ECB_decrypt(String encryptedText, String key) throws Exception {
		// 将Base64编码的字符串解码为字节数组
	    byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
	 
	    // 将密钥字符串转换为字节数组
	    byte[] keyBytes = key.getBytes("UTF-8");
	    SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
	 
	    // 创建Cipher实例，指定AES/ECB/PKCS5Padding模式
	    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    cipher.init(Cipher.DECRYPT_MODE, secretKey);
	 
	    // 解密数据
	    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
	 
	    // 将解密后的字节数组转换为字符串
	    PubkeyData pubkeyData = JSON.parseObject(new String(decryptedBytes, "UTF-8"), PubkeyData.class);
	    return pubkeyData;
	}
	
	public String httpRequest(String url) {
		HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                                         .uri(URI.create(url))
                                         .build();
        HttpResponse<String> response;
		try {
			response = client.send(request, HttpResponse.BodyHandlers.ofString());
			System.out.println(response);
			return response.body();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
        
	}
	
	public ModuleData getModules() {
		return this.module;
	}
	
	public ModuleData getModule(String key) {
		return this.getModuleByKey(this.module, key);
	}
	
	public ModuleData getModuleByKey(ModuleData module, String key) {
		if (module == null) {
			return null;
		}
		if (key.equals(module.getKey())) {
			return module;
		}
		if (module.getChildFuncs() == null) {
			return null;
		}
		
		for (ModuleData m : module.getChildFuncs()) {
			ModuleData ans = this.getModuleByKey(m, key);
			if (ans != null) return ans;
		}
		return null;
	}
	
	public boolean validate(String key) {
		ModuleData module = this.getModuleByKey(this.module, key);
		if (module == null) return false;
		long now = System.currentTimeMillis() / 1000;
		if (module.getExpireTime() < now) {
			return false;
		}
		if (module.getIssuedTime() > now) {
			return false;
		}
		return true;

	}

}


class LicenseWebSocketClient extends WebSocketClient {
	private Client client;
   
    public LicenseWebSocketClient(URI serverUri, Client client) {
        super(serverUri);
        this.client = client;
    }

    @Override
    public void onOpen(ServerHandshake serverHandshake) {
        System.out.println("websocket open");
    }

    @Override
    public void onMessage(String s) {
    	System.out.println("websocket message: " + s);
    	SignData signData = JSON.parseObject(s, SignData.class);
		boolean veryfyResult = this.client.verifyModuleMsg(signData);
		if (!veryfyResult) {
			System.out.println("sign validation is not approved");
			return;
		}
		Base64.Decoder decoder = Base64.getDecoder();
		ModuleData moduleData = JSON.parseObject(new String(decoder.decode(signData.getMsg())), ModuleData.class);
		this.client.module = moduleData;
    }

    @Override
    public void onClose(int i, String s, boolean b) {
    	System.out.println("websocket close");
    }

    @Override
    public void onError(Exception e) {
    	System.out.println("websocket error " + e);
    }


}


//@ClientEndpoint
//class WebSocketClient {
//    private Session session;
//
//    @OnMessage
//    public void onMessage(String message) {
//        System.out.println("Received message: " + message);
//        // 处理接收到的消息
//    }
//
//    public void connect(String url) {
//        WebSocketContainer container = ContainerProvider.getWebSocketContainer();
//        try {
//            session = container.connectToServer(this, new URI(url));
//            System.out.println("websocket: " + url + " connected!");
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//
//    public void close() {
//        try {
//            session.close();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}


//class ModuleData {
//	private String key;
//	private String name;
//	private int issuedTime;
//	private int expireTime;
//	private String extra;
//	private ArrayList<ModuleData> childFuncs;
//	
//	public String getKey() {
//		return key;
//	}
//	public void setKey(String key) {
//		this.key = key;
//	}
//	public String getName() {
//		return name;
//	}
//	public void setName(String name) {
//		this.name = name;
//	}
//	public int getIssuedTime() {
//		return issuedTime;
//	}
//	public void setIssuedTime(int issuedTime) {
//		this.issuedTime = issuedTime;
//	}
//	public int getExpireTime() {
//		return expireTime;
//	}
//	public void setExpireTime(int expireTime) {
//		this.expireTime = expireTime;
//	}
//	public String getExtra() {
//		return extra;
//	}
//	public void setExtra(String extra) {
//		this.extra = extra;
//	}
//	public ArrayList<ModuleData> getChildFuncs() {
//		return childFuncs;
//	}
//	public void setChildFuncs(ArrayList<ModuleData> childFuncs) {
//		this.childFuncs = childFuncs;
//	}
//}


class SignData {
	private String sign;
	private String msg;
	
	public String getSign() {
		return sign;
	}
	public void setSign(String sign) {
		this.sign = sign;
	}
	public String getMsg() {
		return msg;
	}
	public void setMsg(String msg) {
		this.msg = msg;
	}
}

class ModuleResp {
	private int code;
	private String msg;
	private String data;
	public int getCode() {
		return code;
	}
	public void setCode(int code) {
		this.code = code;
	}
	public String getMsg() {
		return msg;
	}
	public void setMsg(String msg) {
		this.msg = msg;
	}
	public String getData() {
		return data;
	}
	public void setData(String data) {
		this.data = data;
	}
}

//class InitResp {
//	private String msg;
//	private Boolean result;
//	
//	public InitResp(String msg, Boolean result) {
//		super();
//		this.msg = msg;
//		this.result = result;
//	}
//	public String getMsg() {
//		return msg;
//	}
//	public void setMsg(String msg) {
//		this.msg = msg;
//	}
//	public Boolean getResult() {
//		return result;
//	}
//	public void setResult(Boolean result) {
//		this.result = result;
//	}
//	
//	
//}

class PubkeyData {
	private String publicKey;
	private String prodKey;
	
	public String getPublicKey() {
		return publicKey;
	}
	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}
	public String getProdKey() {
		return prodKey;
	}
	public void setProdKey(String prodKey) {
		this.prodKey = prodKey;
	}
}

class PubkeyResp {
	private int code;
	private String msg;
	private String data;
	
	public PubkeyResp(int code, String msg, String data) {
		super();
		this.code = code;
		this.msg = msg;
		this.data = data;
	}
	public int getCode() {
		return code;
	}
	public void setCode(int code) {
		this.code = code;
	}
	public String getMsg() {
		return msg;
	}
	public void setMsg(String msg) {
		this.msg = msg;
	}
	public String getData() {
		return data;
	}
	public void setData(String data) {
		this.data = data;
	}
}