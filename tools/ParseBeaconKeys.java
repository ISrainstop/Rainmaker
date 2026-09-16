/*
 * cs_dev :: ParseBeaconKeys.java  --  解析 .cobaltstrike.beacon_keys
 * ==========================================================================
 * 自研 stager 的第一步: 拿到 RSA 公钥, 用于加密 checkin 的 metadata。
 *
 * beacon_keys 的实际格式 (实测文件头):
 *   AC ED 00 05                                  Java 序列化魔数
 *   73 72 00 14 "sleep.runtime.Scalar"           TC_OBJECT + TC_CLASSDESC, 类名长 20
 * 即该文件是一个 sleep.runtime.Scalar 对象的序列化结果, 内部持有 RSA 密钥对。
 *
 * 解析必须借助 CS 自带的类 (sleep.runtime.Scalar 在 cobaltstrike-client.jar 内),
 * 因此运行时需要把该 jar 放进 classpath。
 *
 * 用法:
 *   java -cp "<CS根>/cobaltstrike-client.jar;<编译输出>" ParseBeaconKeys <beacon_keys路径>
 */
import java.io.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class ParseBeaconKeys {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: ParseBeaconKeys <beacon_keys file>");
            System.exit(2);
        }
        File f = new File(args[0]);
        if (!f.exists()) {
            System.err.println("not found: " + f.getAbsolutePath());
            System.exit(2);
        }

        System.out.println("[*] file : " + f.getAbsolutePath());
        System.out.println("[*] size : " + f.length() + " bytes");

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f));
        Object o = ois.readObject();
        ois.close();

        System.out.println("[*] class: " + o.getClass().getName());

        /* Scalar 是 Sleep 的包装类型, 先经其 API 取出底层对象 */
        try {
            Class<?> sc = Class.forName("sleep.runtime.Scalar");
            if (sc.isInstance(o)) {
                java.lang.reflect.Method mv = sc.getMethod("objectValue");
                Object inner = mv.invoke(o);
                System.out.println("[*] objectValue -> " +
                    (inner == null ? "null" : inner.getClass().getName()));
                if (inner != null && inner != o) dump("[inner] ", inner, 0);
            }
        } catch (Throwable t) {
            System.out.println("[!] objectValue failed: " + t);
        }

        dump("", o, 0);
    }

    /* 递归展开 Scalar / Hashtable / 数组, 直到露出 Key 对象 */
    private static void dump(String pad, Object o, int depth) throws Exception {
        if (o == null || depth > 4) return;

        String cls = o.getClass().getName();

        if (o instanceof Key) {
            report(pad, (Key) o);
            return;
        }

        /* KeyPair: 走公开方法取密钥, 避免 JDK 模块系统拦截私有字段反射 */
        if (o instanceof java.security.KeyPair) {
            java.security.KeyPair kp = (java.security.KeyPair) o;
            System.out.println(pad + "== KeyPair ==");
            report(pad + "  [public]  ", kp.getPublic());
            System.out.println(pad + "  [private] : 不导出 (仅 teamserver 持有, 载荷侧不需要)");
            return;
        }

        if (o instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) o;
            System.out.println(pad + "map(" + cls + ") size=" + m.size());
            for (Map.Entry<?, ?> e : m.entrySet()) {
                System.out.println(pad + "  key=" + String.valueOf(e.getKey()));
                dump(pad + "    ", e.getValue(), depth + 1);
            }
            return;
        }

        if (o instanceof Object[]) {
            Object[] arr = (Object[]) o;
            System.out.println(pad + "array(" + cls + ") len=" + arr.length);
            for (Object x : arr) dump(pad + "  ", x, depth + 1);
            return;
        }

        if (o instanceof byte[]) {
            byte[] b = (byte[]) o;
            System.out.println(pad + "byte[] len=" + b.length);
            /* X.509 编码的 RSA 公钥以 30 82 开头 */
            if (b.length > 8 && (b[0] & 0xFF) == 0x30 && (b[1] & 0xFF) == 0x82) {
                try {
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(b));
                    report(pad + "  ", pk);
                    return;
                } catch (Exception ignore) { }
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Math.min(b.length, 16); i++) sb.append(String.format("%02X ", b[i]));
            System.out.println(pad + "  head: " + sb.toString().trim());
            return;
        }

        /* 其余对象 (含 sleep.runtime.Scalar): 遍历全部字段, 打印类型后继续下潜 */
        System.out.println(pad + "obj(" + cls + ")");
        for (Class<?> c = o.getClass(); c != null && c != Object.class; c = c.getSuperclass()) {
            for (java.lang.reflect.Field fd : c.getDeclaredFields()) {
                Object v = null;
                try {
                    fd.setAccessible(true);
                    v = fd.get(o);
                } catch (Throwable t) {
                    System.out.println(pad + "  field " + fd.getName() + " : <inaccessible>");
                    continue;
                }
                String vt = (v == null) ? "null" : v.getClass().getName();
                String vs = (v == null || v instanceof Number || v instanceof Boolean
                             || v instanceof String)
                            ? String.valueOf(v) : "";
                System.out.println(pad + "  field " + fd.getName() + " : " + vt +
                                   (vs.isEmpty() ? "" : " = " + vs));
                if (v != null && !(v instanceof Number) && !(v instanceof Boolean)
                    && !(v instanceof String) && !(v instanceof Character)) {
                    dump(pad + "    ", v, depth + 1);
                }
            }
        }
    }

    private static void report(String pad, Key k) {
        System.out.println(pad + "== KEY ==");
        System.out.println(pad + "  algorithm : " + k.getAlgorithm());
        System.out.println(pad + "  format    : " + k.getFormat());
        if (k instanceof RSAPublicKey) {
            RSAPublicKey rk = (RSAPublicKey) k;
            System.out.println(pad + "  modulus   : " + rk.getModulus().bitLength() + " bits");
            System.out.println(pad + "  e         : " + rk.getPublicExponent());
            System.out.println(pad + "  X509 b64  : " + Base64.getEncoder().encodeToString(k.getEncoded()));
        } else if (k instanceof RSAPrivateKey) {
            RSAPrivateKey rk = (RSAPrivateKey) k;
            System.out.println(pad + "  modulus   : " + rk.getModulus().bitLength() + " bits");
        }
    }
}
