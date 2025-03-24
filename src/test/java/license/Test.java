package license;

public class Test {
	public static void main(String[] args) throws Exception {
		// 初始化sdk client
		Client c = new Client("localhost:18080", "10002");
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

	}
}