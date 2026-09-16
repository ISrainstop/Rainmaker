/*
 * cs_dev :: ValidateProfile.java  --  用 CS 自带的解析器校验 Malleable C2 Profile
 * ==========================================================================
 * Profile 语法错误会导致 teamserver 无法启动, 因此提交前必须用 CS 自己的
 * c2profile.Profile 类做一次真实解析, 而不是靠肉眼对比。
 *
 * 用法:
 *   java -cp "<CS根>/cobaltstrike-client.jar;<本文件输出目录>" ValidateProfile <profile文件>
 */
import java.io.File;

public class ValidateProfile {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: ValidateProfile <profile file>");
            System.exit(2);
        }
        File f = new File(args[0]);
        if (!f.exists()) {
            System.err.println("[!] 文件不存在: " + f.getAbsolutePath());
            System.exit(2);
        }

        System.out.println("[*] 文件 : " + f.getAbsolutePath());
        System.out.println("[*] 大小 : " + f.length() + " 字节");
        System.out.println();

        boolean ok = false;
        try {
            c2profile.Profile p = new c2profile.Profile();
            p.load(f);
            p.addParameter("useragent", "x");   // 触发一次完整语法检查

            System.out.println("[+] 解析成功, 无语法错误");
            ok = true;

            /* 把关键选项回读出来, 确认配置真的生效 */
            System.out.println();
            System.out.println("=== 回读关键选项 ===");
            String[][] probes = {
                {".sleeptime",        ""},
                {".jitter",           ""},
                {".sample_name",      ""},
                {".http-get.uri",     ""},
                {".http-post.uri",    ""},
                {".http-get.client.metadata", ""},
                {".stage.name",       ""},
                {".dns-beacon.get_A", ""},
            };
            for (String[] pr : probes) {
                try {
                    String v = p.getString(pr[0]);
                    System.out.println(String.format("  %-30s = %s", pr[0],
                        (v == null ? "<null>" : v)));
                } catch (Throwable t) {
                    System.out.println(String.format("  %-30s : 读取异常 %s", pr[0], t));
                }
            }
        } catch (Throwable t) {
            System.out.println("[-] 解析失败: " + t);
            String m = String.valueOf(t.getMessage());
            if (m != null && m.length() > 0) {
                System.out.println("    详情: " + m);
            }
        }

        System.out.println();
        System.out.println(ok ? "[结果] Profile 可用" : "[结果] Profile 有错误, 需修正");
        System.exit(ok ? 0 : 1);
    }
}
