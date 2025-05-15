### 概述
标品方成功申请证书后，需要使用SDK校验标品的某些功能模块是否可用，证书中所包含的功能模块，允许用户访问使用，证书中不包含的功能模块，标品方通过SDK校验后，需要进行拦截，不允许使用该功能模块

### SDK使用方法

### 1 安装(pom.xml)
#### 在pom.xml添加引用
```bash
 
<dependencies>
	<dependency>
		<groupId>io.github.qiaoyk666</groupId>
		<artifactId>license-sdk-java</artifactId>
		<version>0.0.9</version>
	</dependency>
</dependencies>

```
### 2 SDK类型说明
```
// SDK初始化结果
class InitResp {
	private String msg; // 错误信息
	private Boolean result; // 初始化是否成功，true:成功，false:失败
}

// 模块树形结构
class ModuleData {
	private String key; // 模块key
	private String name; // 模块名称
	private int issuedTime; // 生效时间
	private int expireTime; // 过期效期
	private String extra; 
	private ArrayList<ModuleData> childFuncs;
}	

// 监听事件类型
enum EventType {
	LicenseChange("license_change"), // 证书变化事件，比如证书有效期的变更，权限树的修改等
	ConnectionError("connection_error"), // websocket连接异常事件
	LicenseExpiring("license_expiring"), // 证书即将过期事件
	LicenseRevoke("license_revoke"); // 证书吊销事件，证书吊销后，所有功能模块不可用
}
```

### 3 SDK方法说明
- init(String endPoint, String prodkey, String secretKey) 初始化sdk
	- endPoint: 许可服务地址
	- prodkey: 标品id
	- secretKey: 密钥
- getModules() 获取标品的权限树
- getModule(String key)  获取指定key的权限树
- validate(String key) 校验证书是否有这个key的权限
- getRemainingDays() 获取证书剩余有效期天数


### 4 Client使用
```bash

package license;
import com.alibaba.fastjson.JSONObject;
import license.CallbackFunction;
import license.Client;
import license.EventType;
import license.InitResp;
import license.ModuleData;

public class Test {
	public static void main(String[] args) throws Exception {
		// 初始化sdk client
		Client c = new Client("http://ip:port", "your prodkey", "your secret key");
		InitResp initResult = c.init();
		if (initResult.getResult() == false) {
			System.out.println("sdk client init failed");
			return;
		}
		
		// 获取权限树
		ModuleData modules = c.getModules();
		System.out.println(modules.getName());

		// 获取指定key的权限树
		String key1 = "10002.10004";
		ModuleData module = c.getModule("10002.10004");
		if (module != null) {
			System.out.println("module.key:" + module.getKey() + " module.name:" + module.getName());
		} else {
			System.out.println("key: " + key1 + " is not found");
			return;
		}
	
		// 校验指定key是否有权限
		String key = "10002.10004";
		boolean isOk = c.validate(key);
		if (isOk) {
			System.out.println("key: " + key + " has permission");
		} else {
			System.out.println("key: " + key + " has no permission");
		}

		long days = c.getRemainingDays();
		System.out.println("证书剩余有效期天数：" + days);

		//监听证书变化
		c.on(EventType.LicenseChange, new CallbackFunction() {

			@Override
			public void execute(ModuleData data) {
				System.out.println("license_change_callback data:" + JSONObject.toJSONString(data));
			}
		});
		
		//监听证书还剩多少天过期
		c.on(EventType.LicenseExpiring, new CallbackFunction() {
			@Override
			public void execute(Object data) {
				// 返回结果示例 { day: 16 }
				System.out.println("license_expiring_callback data:" + data); 
			}
		});
		
		// 监听证书撤销事件
		c.on(EventType.LicenseRevoke, new CallbackFunction() {
			@Override
			public void execute(ModuleData data) {
				System.out.println("license_revoke_callback data:" + data);
			}
		});

		// 监听ws连接异常
		c.on(EventType.ConnectionError, new CallbackFunction() {
			@Override
			public void execute(Object data) {
				// 返回数据示例：
				// Error: connect ECONNREFUSED ::1:18080
				System.out.println("websocket Error connection:" + data);
			}
		});
	}
}
```