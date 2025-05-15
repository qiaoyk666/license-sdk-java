package license;

import com.alibaba.fastjson.JSONObject;

public class Test {
	public static void main(String[] args) throws Exception {
		// 初始化sdk client
		Client c = new Client("http://ip:port", "your prodkey", "your secret key");
		InitResp initResult = c.init();
		System.out.println(initResult.getMsg());
		if (initResult.getResult() == false) {
			System.out.println("sdk client init failed");
			return;
		}

		// 获取权限树
		ModuleData modules = c.getModules();
		System.out.println(modules.getName());

		// 获取指定key的权限树
		String key1 = "znjy000.1000";
		ModuleData module = c.getModule(key1);
		if (module != null) {
			System.out.println("module.key:" + module.getKey() + " module.name:" + module.getName());
		} else {
			System.out.println("key: " + key1 + " is not found");
			return;
		}

		// 校验指定key是否有权限
		String key = "znjy000.1000";
		boolean isOk = c.validate(key);
		if (isOk) {
			System.out.println("key: " + key + " has permission");
		} else {
			System.out.println("key: " + key + " has no permission");
		}

		int days = c.getRemainingDays();
		System.out.println("证书剩余有效期天数：" + days);

		// 监听证书变化
		c.on(EventType.LicenseChange, new CallbackFunction() {

			@Override
			public void execute(Object data) {
				System.out.println("license_change_callback data:" + JSONObject.toJSONString(data));
			}

		});

		// 监听证书还剩多少天过期
		c.on(EventType.LicenseExpiring, new CallbackFunction() {

			@Override
			public void execute(Object data) {
				System.out.println("license_expiring_callback data:" + data); // {"day": 176}
			}
		});
		
		// 监听证书撤销事件
		c.on(EventType.LicenseRevoke, new CallbackFunction() {

			@Override
			public void execute(Object data) {
				System.out.println("license_revoke_callback data:" + data);
			}
		});
		

		// 监听ws连接异常
		c.on(EventType.ConnectionError, new CallbackFunction() {

			@Override
			public void execute(Object data) {
				System.out.println("websocket Error connection:" + data);
			}
		});
	}

}