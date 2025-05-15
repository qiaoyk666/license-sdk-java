package license;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.drafts.Draft;
import org.java_websocket.handshake.ServerHandshake;

import com.alibaba.fastjson2.JSON;



public class Client {
	//	服务地址
	private String endpoint;
	//	标品id
	private String prodKey;
	// 客户端公钥
	private String publicKey;
	ModuleData module;
	int maxReconnectAttempts = 10;
	int reconnectAttempt = 0;
	int reconnectWaitTimeSecond = 3;
	private int heartbeatInterval = 15; // 15秒
	ScheduledFuture<?> future;
	
	private String secretKey;
	
	private Map<EventType, ArrayList<CallbackFunction>> eventCallbacks = new HashMap<EventType, ArrayList<CallbackFunction>>(); 
	private LicenseWebSocketClient wsClient;
//	private SSLWebSocketClient wsClient;
	
	public Client(String endpoint, String prodKey, String secretKey) {
		this.endpoint = endpoint;
		this.prodKey = prodKey;
		this.secretKey = secretKey;
		this.eventCallbacks.put(EventType.LicenseChange, new ArrayList<CallbackFunction>());
		this.eventCallbacks.put(EventType.LicenseExpiring, new ArrayList<CallbackFunction>());
		this.eventCallbacks.put(EventType.ConnectionError, new ArrayList<CallbackFunction>());
		this.eventCallbacks.put(EventType.LicenseRevoke, new ArrayList<CallbackFunction>());
	}
	
	public InitResp init() throws Exception {	
		InitResp initResp = new InitResp("", false);
		
		// 1. 获取公钥
		String resp = this.httpRequest3(this.endpoint+"/pubkey?prodkey="+this.prodKey);
		PubkeyResp pubResp = JSON.parseObject(resp, PubkeyResp.class);
		if (pubResp.getCode() != 200) {
			String msg = "failed to get auth info: " + pubResp.getMsg();
			initResp.setMsg(msg);
			return initResp;
		}
		
		// 2. AES解密返回的数据
		PubkeyData pubkeyData;
		try {
			pubkeyData = this.aes_ECB_decrypt(pubResp.getData(), secretKey.substring(0, 32));
			if (!this.prodKey.equals(pubkeyData.getProdKey())) {
				String msg = "prodkey not match";
				initResp.setMsg(msg);
				return initResp;
			}
		} catch (Exception e) {
			e.printStackTrace();
			String msg = "aes decrypt data error: " + e;
			initResp.setMsg(msg);
			return initResp;
		}
		
		this.publicKey = pubkeyData.getPublicKey();
		
		// 3. 获取权限树
		String moduleRespStr = this.httpRequest3(this.endpoint+"/modules?prodkey="+this.prodKey);
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
		
		// 5. 开启websocket监听
		this.connectWebSocket();
		
		this.heartbeat();
		
		initResp.setResult(true);
		return initResp;
	}
	
	private void heartbeat() {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        
        Runnable task = () -> {
            System.out.println("Executing task at " + LocalDateTime.now());
            
            // 构造心跳消息
            HeartbeatMsg heartbeatMsg = new HeartbeatMsg(MsgType.MsgTypeHeartbeat, "ping");
            
            try {
            	if (this.wsClient == null) {
            		this.resetWsClient();
            	}
				this.wsClient.send(JSON.toJSONString(heartbeatMsg));
			} catch (Exception e) {
				System.out.println("sdk ws heartbeat error ");
//				e.printStackTrace();
				this.future.cancel(true);
			}
        };
 
        // 固定延迟模式，初始延迟0秒，间隔15秒执行一次
        this.future = scheduler.scheduleAtFixedRate(task, 0, this.heartbeatInterval, TimeUnit.SECONDS);
        
	}
	
	void reconnect() {
		if (this.wsClient != null) {
			this.wsClient.close();
			this.wsClient = null;
		}
		
		if (this.reconnectAttempt > this.maxReconnectAttempts) {
			String msg = "reconnection reached max attemps";
			System.out.println(msg);
			this.emit(EventType.ConnectionError, new Error(msg));
			return;
		}
		this.reconnectAttempt++;
		System.out.println("attempting to reconnect ws times: " + this.reconnectAttempt);
		
		
		try {
			// 延时
//			Thread.currentThread().interrupt();
			Thread.sleep(this.reconnectWaitTimeSecond * 1000);
			this.connectWebSocket();
			this.heartbeat();
		} catch (InterruptedException e) {// TODO Auto-generated catch block
//			e.printStackTrace();
//			Thread.currentThread().interrupt();
			// 出错后，尝试重连，直到达到设定的重连次数
			this.reconnect();
		}
		
	}
	
	public byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] byteArray = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            // 将每两个十六进制字符转换为一个字节
            byteArray[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                                     + Character.digit(hexString.charAt(i+1), 16));
        }
        return byteArray;
    }
	
	private void handleWebSocket() {
//		try {
//        	this.wsClient = new LicenseWebSocketClient(new URI("ws://" + this.endpoint + "/ws?prodkey=" + this.prodKey), this);
        	
        	if (this.wsClient == null) {
        		this.resetWsClient();
        	}
//        	this.wsClient.connect();
//            while (this.wsClient != null && !this.wsClient.getReadyState().equals(WebSocket.READYSTATE.OPEN)) {
//                System.out.println("连接中。。。");
//                try {
//					Thread.sleep(1000);
//				} catch (InterruptedException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//					Thread.currentThread().interrupt();
//				}
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
	}
	
	private void resetWsClient() {
		if (this.wsClient != null) {
			this.wsClient.close();
			this.wsClient = null;
		}
		String wsUrl = this.getWsUrl();
		try {
			this.wsClient = new LicenseWebSocketClient(new URI(wsUrl), this);
			this.wsClient.connect();
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		
		//此处填写你需要连接的WebSocket地址
//	    URI uri = URI.create(wsUrl);
//	    try {
////			SSLSocketFactory socketFactory = this.getSocketFactory();
//			this.wsClient = new LicenseWebSocketClient(new URI(wsUrl), this);
//			
////			this.wsClient = this.getSSLWebSocketClient(wsUrl, this);
////			this.wsClient.connect();
////			this.wsClient.setSocketFactory(socketFactory);
//	    } catch (URISyntaxException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}

	}
	
	private SSLSocketFactory getSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
		TrustManager trustManager = new X509ExtendedTrustManager() {
	        @Override
	        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
	 
	        }
	 
	        @Override
	        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
	 
	        }
	 
	        @Override
	        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
	 
	        }
	 
	        @Override
	        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
	 
	        }
	 
	        @Override
	        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
	 
	        }
	 
	        @Override
	        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
	 
	        }
	 
	        @Override
	        public X509Certificate[] getAcceptedIssuers() {
	            return new X509Certificate[]{};
	        }
	    };
	    SSLContext sslContext = SSLContext.getInstance("TLS");
	    sslContext.init(null, new TrustManager[]{trustManager}, null);
	 
	    
	    SSLSocketFactory socketFactory = sslContext.getSocketFactory();
	    return socketFactory;
	}
	
	private void connectWebSocket() {
		this.resetWsClient();
		this.handleWebSocket();
	}
	
	private String getWsUrl() {
		String url = this.endpoint;
		String protocol = "ws";
		if (this.endpoint.contains("https://")) {
			url = this.endpoint.split("https://")[1];
			protocol = "wss";
		} else if (this.endpoint.contains("http://")) {
			url = this.endpoint.split("http://")[1];
		}
		return protocol + "://" + url + "/ws?prodkey=" + this.prodKey;
	}
	
	public boolean verifyModuleMsg(SignData signData) {
		return this.verifySign(this.publicKey, signData.getSign(), signData.getMsg());
	}
	
	private boolean verifySign(String pubkey, String sign, String msg) {
//		// 将十六进制字符串转换为字节数组
//		Base64.Decoder decoder = Base64.getDecoder();
//		
//        byte[] publicKeyBytes = new BigInteger(pubkey, 16).toByteArray();   
//        byte[] signatureBytes = decoder.decode(sign);
//        byte[] messageBytes = decoder.decode(msg);
//        
//        
//        // 创建Ed25519公钥参数
//        Ed25519PublicKeyParameters publicKeyParams = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
//
//        // 创建签名验证器
//        Signer signer = new Ed25519Signer();
//        signer.init(false, publicKeyParams);
//        signer.update(messageBytes, 0, messageBytes.length);
//
//        // 验证签名
//        boolean isValid = signer.verifySignature(signatureBytes);
//        System.out.println("签名是否有效: " + isValid);
            
		Base64.Decoder decoder = Base64.getDecoder();
        byte[] publicKeyBytes = hexStringToByteArray(pubkey);
        byte[] signatureBytes = decoder.decode(sign);
        byte[] messageBytes = decoder.decode(msg);
        
        // 将公钥转换为Ed25519PublicKeyParameters
        Ed25519PublicKeyParameters publicKeyParameters = new Ed25519PublicKeyParameters(publicKeyBytes, 0);

        // 验证签名
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, publicKeyParameters);
        verifier.update(messageBytes, 0, messageBytes.length);

        boolean isVerified = verifier.verifySignature(signatureBytes);
        System.out.println("签名是否有效: " + isVerified);

        return isVerified;
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
	
	public String httpRequest3(String url) throws Exception {
		// 创建一个不校验任何证书的TrustManager
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }
        };
 
        // 初始化SSLContext对象，使用我们自定义的TrustManager
        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, trustAllCerts, new SecureRandom());
 
        // 使用HttpClient并配置SSLContext
        HttpClient client = HttpClient.newBuilder()
            .sslContext(sslContext)
            .build();
 
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .build();
 
        HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
        System.out.println(response.body());
        return response.body();
    
	}
	
//	public String httpRequest2(String url) {
//		// 创建一个信任所有证书的TrustStrategy
//        TrustStrategy trustStrategy = (X509Certificate[] chain, String authType) -> true;
//        SSLContext sslContext = SSLContexts.custom()
//            .loadTrustMaterial(null, trustStrategy)
//            .build();
//        PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager(org.apache.hc.client5.http.ssl.SSLContexts.custom()
//             .loadTrustMaterial(null, trustStrategy)
//             .build());
//        CloseableHttpClient httpClient = HttpClients.custom()
//             .setSSLSocketFactory(new SSLConnectionSocketFactory(sslContext))
//             .setConnectionManager(cm)
//             .build();
//             
//        HttpGet httpGet = new HttpGet("https://your-server.com");
//        CloseableHttpResponse response = httpClient.execute(httpGet);
//        System.out.println(response); // 处理响应...
//		
//		return "";
//	}
	
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
	public int getRemainingDays() {
		ModuleData module = this.module;
		long now = System.currentTimeMillis() / 1000;
		double seconds = module.getExpireTime() - now;
		int result = (int) Math.ceil(seconds / 3600 / 24);
		return result;
	}
	
	public void emit(EventType event, Object data) {
		ArrayList<CallbackFunction> callbacks = this.eventCallbacks.get(event);

		for (CallbackFunction caller : callbacks) {
			caller.execute(data);
		}
	}
	
	
	public void on(EventType event, CallbackFunction Caller) {
		(this.eventCallbacks.get(event)).add(Caller);
	}

	
	private SSLWebSocketClient getSSLWebSocketClient(String url, Client c) throws URISyntaxException {
		SSLWebSocketClient client = new SSLWebSocketClient(new URI(url)){
			@Override
			public void onClose(int arg0, String arg1, boolean arg2){
				System.out.println("websocket close");
		    	c.future.cancel(true);
		    	if (c.reconnectAttempt >= c.maxReconnectAttempts) {
		    		System.out.println("reconnection reached max attemps");
		    		return;
		    	}
		    	c.reconnect();
			}
			@Override
			public void onError(Exception arg0){
				System.out.println("websocket error: " + arg0);
		    	c.emit(EventType.ConnectionError, arg0);
			}
			@Override
			public void onMessage(String s){
				System.out.println("onMessage");
				
				
				System.out.println("websocket message: " + s);
		    	SignData signData = JSON.parseObject(s, SignData.class);
		    	Base64.Decoder decoder = Base64.getDecoder();
		    	
		    	
		    	switch (MsgType.fromValue(signData.getMsgType())) {
			    	case WsMsgTypePermissionTree:
			    		boolean veryfyResult = c.verifyModuleMsg(signData);
			    		if (!veryfyResult) {
			    			System.out.println("sign validation is not approved");
			    			return;
			    		}
			    		ModuleData moduleData = JSON.parseObject(new String(decoder.decode(signData.getMsg())), ModuleData.class);
			    		c.module = moduleData;
			    		c.emit(EventType.LicenseChange, moduleData);
			    		break;
			    	case WsMsgTypeExpireWarning:
			    		String msg = new String(decoder.decode(signData.getMsg()));
			    		System.out.println("WsMsgTypeExpireWarning msg: " + msg);
			    		c.emit(EventType.LicenseExpiring, JSON.parse(msg));
			    		break;
			    	case WsMsgTypeRevokeLicense:
			    		String msgRevoke = new String(decoder.decode(signData.getMsg()));
			    		System.out.println("WsMsgTypeRevokeLicense msg: " + msgRevoke);
			    		c.emit(EventType.LicenseRevoke, JSON.parse(msgRevoke));
			    		break;
			    	case MsgTypeHeartbeat:
			    		String msgheartBeat = new String(decoder.decode(signData.getMsg()));
			    		System.out.println("MsgTypeHeartbeat msg: " + msgheartBeat);
			    		break;
			    		
		    	}
		    	
			}
			@Override
			public void onOpen(ServerHandshake arg0){
				System.out.println("websocket open");
		        c.reconnectAttempt = 0;
			}
		};
//		.connect();

		return client;
	}

}

/**
* 构建 SSLWebSocket客户端，忽略证书
*/
class SSLWebSocketClient extends WebSocketClient{
	//构造方法
//	public SSLWebSocketClient(URI serverURI,String message){
	public SSLWebSocketClient(URI serverURI){
		super(serverURI);
		if(serverURI.toString().contains("wss://")){
			System.out.println("------------------>>>>>>>>>>>>>><<<<<<<<<<<<<<<<");
			trustAllHosts(this);
//			this.send(message);
		}
	}
	public SSLWebSocketClient(URI serverURI,Draft draft){
		super(serverURI,draft);
		if(serverURI.toString().contains("wss://"))
			trustAllHosts(this);
		}
	/**
	* 忽略证书
	* @param client
	*/
	void trustAllHosts(SSLWebSocketClient client){
//		TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager(){
//			public java.security.cert.X509Certificate[] getAcceptedIssuers(){
//				return new java.security.cert.X509Certificate[]{};
//			}
//			@Override
//			public void checkClientTrusted(X509Certificate[] arg0,String arg1)throws CertificateException{
//			}
//			@Override
//			public void checkServerTrusted(X509Certificate[] arg0,String arg1)throws CertificateException{
//			}
//		}};
//		try{
//			SSLContext ssl = SSLContext.getInstance("TLS");
//			ssl.init(null, trustAllCerts, new java.security.SecureRandom());
//		}catch(Exception e){
//			e.printStackTrace();
//		}
		
		
		
		TrustManager[] trustAllCerts = new TrustManager[]{new X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {

            }

            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {

            }

            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
//                return new java.security.cert.X509Certificate[]{};
//                System.out.println("getAcceptedIssuers");
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                System.out.println("checkClientTrusted");
            }

            @Override
            public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                System.out.println("checkServerTrusted");
            }
        }};

        try {

            SSLContext ssl = SSLContext.getInstance("SSL");
            ssl.init(null, trustAllCerts, new java.security.SecureRandom());

            SSLSocketFactory socketFactory = ssl.getSocketFactory();
//            this.setSocketFactory(socketFactory);
        } catch (Exception e) {
            e.printStackTrace();
        }
		
		
	}
	@Override
	public void onOpen(ServerHandshake handshakedata) {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void onMessage(String message) {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void onClose(int code, String reason, boolean remote) {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void onError(Exception ex) {
		// TODO Auto-generated method stub
		
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
        this.client.reconnectAttempt = 0;
    }

    @Override
    public void onMessage(String s) {
    	System.out.println("websocket message: " + s);
    	SignData signData = JSON.parseObject(s, SignData.class);
    	Base64.Decoder decoder = Base64.getDecoder();
//    	if (signData.getMsgType() == int(MsgType.WsMsgTypePermissionTree)) {
//    	if (signData.getMsgType() == 1) {
//    		boolean veryfyResult = this.client.verifyModuleMsg(signData);
//    		if (!veryfyResult) {
//    			System.out.println("sign validation is not approved");
//    			return;
//    		}
//    		ModuleData moduleData = JSON.parseObject(new String(decoder.decode(signData.getMsg())), ModuleData.class);
//    		this.client.module = moduleData;
//    		this.client.emit(EventType.LicenseChange, moduleData);
//    		
////    	} else if (signData.getMsgType() == MsgType.WsMsgTypeExpireWarning) {
//    	} else if (signData.getMsgType() == 2) {
//    		String msg = new String(decoder.decode(signData.getMsg()));
//    		System.out.println("msg-----" + msg);
//    		this.client.emit(EventType.LicenseExpiring, JSON.parse(msg));
//    	}
    	
    	
    	switch (MsgType.fromValue(signData.getMsgType())) {
	    	case WsMsgTypePermissionTree:
	    		boolean veryfyResult = this.client.verifyModuleMsg(signData);
	    		if (!veryfyResult) {
	    			System.out.println("sign validation is not approved");
	    			return;
	    		}
	    		ModuleData moduleData = JSON.parseObject(new String(decoder.decode(signData.getMsg())), ModuleData.class);
	    		this.client.module = moduleData;
	    		this.client.emit(EventType.LicenseChange, moduleData);
	    		break;
	    	case WsMsgTypeExpireWarning:
	    		String msg = new String(decoder.decode(signData.getMsg()));
	    		System.out.println("WsMsgTypeExpireWarning msg: " + msg);
	    		this.client.emit(EventType.LicenseExpiring, JSON.parse(msg));
	    		break;
	    	case WsMsgTypeRevokeLicense:
	    		String msgRevoke = new String(decoder.decode(signData.getMsg()));
	    		System.out.println("WsMsgTypeRevokeLicense msg: " + msgRevoke);
	    		this.client.emit(EventType.LicenseRevoke, JSON.parse(msgRevoke));
	    		break;
	    	case MsgTypeHeartbeat:
	    		String msgheartBeat = new String(decoder.decode(signData.getMsg()));
	    		System.out.println("MsgTypeHeartbeat msg: " + msgheartBeat);
	    		break;
	    		
    	}
    	
		
    }

    @Override
    public void onClose(int i, String s, boolean b) {
    	System.out.println("websocket close");
    	this.client.future.cancel(true);
    	if (this.client.reconnectAttempt >= this.client.maxReconnectAttempts) {
    		System.out.println("reconnection reached max attemps");
    		return;
    	}
    	this.client.reconnect();
//    	try {
//    		this.client.future.cancel(false);
//			Thread.sleep(this.client.reconnectWaitTimeSecond);
//			this.client.reconnect();
//		} catch (InterruptedException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
    }

    @Override
    public void onError(Exception e) {
    	System.out.println("websocket error: " + e);
    	this.client.emit(EventType.ConnectionError, e);
    }

    
    /**
     *忽略证书
     *@paramclient
     */
//    void trustAllHosts(WebSocketClient client) {
//    	TrustManager[] trustAllCerts = new TrustManager[]{new X509ExtendedTrustManager() {
//            @Override
//            public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
//
//            }
//
//            @Override
//            public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
//
//            }
//
//            @Override
//            public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
//
//            }
//
//            @Override
//            public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
//
//            }
//
//            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
////                return new java.security.cert.X509Certificate[]{};
////                System.out.println("getAcceptedIssuers");
//                return null;
//            }
//
//            @Override
//            public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
//                System.out.println("checkClientTrusted");
//            }
//
//            @Override
//            public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
//                System.out.println("checkServerTrusted");
//            }
//        }};
//
//        try {
//
//            SSLContext ssl = SSLContext.getInstance("SSL");
//            ssl.init(null, trustAllCerts, new java.security.SecureRandom());
//
//            SSLSocketFactory socketFactory = ssl.getSocketFactory();
//            client.setSocketFactory(socketFactory);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }


}




class SignData {
	
	private String sign;
	private String msg;
	private int msgType;
	
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
	public int getMsgType() {
		return msgType;
	}
	public void setMsgType(int msgType) {
		this.msgType = msgType;
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



class CustomSSLContextFactory {
    public static SSLContext create() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[]{};
                }
 
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }
 
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }}, new java.security.SecureRandom());
            return sslContext;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}