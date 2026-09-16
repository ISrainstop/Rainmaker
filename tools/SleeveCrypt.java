/*
 * SleeveCrypt - Cobalt Strike 4.x sleeved resource 解密/加密工具
 *
 * 用途:
 *   1. 从 cobaltstrike.auth 提取 sleeve master key (公钥手工 RSA 解密 + PKCS#1 v1.5 去填充)
 *   2. decrypt: sleeve/*.o 等加密资源 -> 明文 (COFF/DLL/二进制)
 *   3. encrypt: 明文 -> CS 可加载的加密资源 (用于替换自定义 kit)
 *
 * 算法 (源自 common/SleeveSecurity + common/AuthCrypto):
 *   key_material = SHA256(master)
 *   AES-128-CBC  key = key_material[0:16]   IV = "abcdefghijklmnop"  (NoPadding)
 *   HMAC-SHA256  key = key_material[16:32]
 *   密文格式 = AES-CBC(rand[4] || len[4] || data || 'A'*pad) || HMAC[0:16]
 *
 * 用法:
 *   java SleeveCrypt key  <authkey.pub> <cobaltstrike.auth>            -> 打印 master key hex
 *   java SleeveCrypt dec  <authkey.pub> <cobaltstrike.auth> <in> <out>
 *   java SleeveCrypt enc  <authkey.pub> <cobaltstrike.auth> <in> <out>
 *   java SleeveCrypt decraw <masterkey_hex> <in> <out>
 *   java SleeveCrypt encraw <masterkey_hex> <in> <out>
 */
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

public class SleeveCrypt {

    private static final byte[] IV = "abcdefghijklmnop".getBytes();
    private static final int AUTHORIZATION_HEADER = -889274157;

    /** 手工 RSA 公钥解密 + PKCS#1 v1.5 去填充 (JDK 不允许 Cipher 用公钥解密) */
    static byte[] rsaPublicDecrypt(byte[] pubDer, byte[] block) throws Exception {
        RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(pubDer));
        BigInteger n = pub.getModulus();
        BigInteger e = pub.getPublicExponent();
        BigInteger m = new BigInteger(1, block).modPow(e, n);

        byte[] em = toFixed(m, block.length);
        // PKCS#1 v1.5: 00 01 FF..FF 00 <message>
        if (em[0] != 0x00 || em[1] != 0x01)
            throw new IllegalStateException("bad PKCS1 block header");
        int i = 2;
        while (i < em.length && (em[i] & 0xff) == 0xff) i++;
        if (i >= em.length || em[i] != 0x00)
            throw new IllegalStateException("bad PKCS1 separator");
        return Arrays.copyOfRange(em, i + 1, em.length);
    }

    static byte[] toFixed(BigInteger v, int len) {
        byte[] b = v.toByteArray();
        if (b.length == len) return b;
        byte[] out = new byte[len];
        if (b.length > len) System.arraycopy(b, b.length - len, out, 0, len);
        else System.arraycopy(b, 0, out, len - b.length, b.length);
        return out;
    }

    /**
     * 从 auth 文件解析 sleeve master key (两层结构)
     *
     * 第一层 (AuthCrypto.decrypt):
     *   RSA 公钥解密 -> [int header][short len][byte[len] inner]
     * 第二层 (Authorization 构造函数):
     *   inner: [int validto][int watermark][byte version]
     *          [6 x (byte L + L bytes)]
     *          [int hashLen][hash]
     *          [2 x (byte L + L bytes)]
     *          [byte keyLen][key]        <-- 这才是 SleevedResource.Setup 的入参
     */
    static byte[] masterKey(byte[] pub, byte[] auth) throws Exception {
        byte[] outer = rsaPublicDecrypt(pub, Arrays.copyOfRange(auth, 0, 256));
        int header = beInt(outer, 0);
        if (header != AUTHORIZATION_HEADER)
            throw new IllegalStateException("bad auth header: " + header);

        int len = beShort(outer, 4);
        byte[] inner = Arrays.copyOfRange(outer, 6, 6 + len);

        int p = 0;
        int validto   = beInt(inner, p); p += 4;
        int watermark = beInt(inner, p); p += 4;
        int version   = inner[p] & 0xFF; p += 1;
        System.out.println("[*] auth version=" + version
                           + " watermark=" + watermark
                           + " validto=" + validto);

        for (int i = 0; i < 6; i++) {          // 6 段保留区
            int n = inner[p] & 0xFF; p += 1 + n;
        }
        int hashLen = beInt(inner, p); p += 4; // watermark hash
        if (hashLen > 0) p += hashLen;
        for (int i = 0; i < 2; i++) {          // 2 段保留区
            int n = inner[p] & 0xFF; p += 1 + n;
        }
        int keyLen = inner[p] & 0xFF; p += 1;
        byte[] key = Arrays.copyOfRange(inner, p, p + keyLen);
        System.out.println("[*] sleeve key length = " + keyLen);
        return key;
    }

    static int beInt(byte[] b, int o) {
        return ((b[o] & 0xff) << 24) | ((b[o+1] & 0xff) << 16) | ((b[o+2] & 0xff) << 8) | (b[o+3] & 0xff);
    }

    static int beShort(byte[] b, int o) {
        return ((b[o] & 0xff) << 8) | (b[o+1] & 0xff);
    }

    static byte[] deriveAes(byte[] master) throws Exception {
        return Arrays.copyOfRange(MessageDigest.getInstance("SHA-256").digest(master), 0, 16);
    }

    static byte[] deriveMac(byte[] master) throws Exception {
        return Arrays.copyOfRange(MessageDigest.getInstance("SHA-256").digest(master), 16, 32);
    }

    public static byte[] decrypt(byte[] master, byte[] in) throws Exception {
        byte[] payload = Arrays.copyOfRange(in, 0, in.length - 16);
        byte[] hmac = Arrays.copyOfRange(in, in.length - 16, in.length);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(deriveMac(master), "HmacSHA256"));
        byte[] expect = Arrays.copyOfRange(mac.doFinal(payload), 0, 16);
        if (!MessageDigest.isEqual(hmac, expect))
            throw new IllegalStateException("HMAC mismatch - wrong key or corrupt resource");

        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(deriveAes(master), "AES"), new IvParameterSpec(IV));
        byte[] plain = c.doFinal(payload);

        int len = beInt(plain, 4);
        if (len < 0 || len > plain.length)
            throw new IllegalStateException("impossible message length: " + len);
        return Arrays.copyOfRange(plain, 8, 8 + len);
    }

    public static byte[] encrypt(byte[] master, byte[] data) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length + 32);
        int rnd = new Random().nextInt(Integer.MAX_VALUE);
        bos.write(new byte[]{(byte)(rnd >>> 24), (byte)(rnd >>> 16), (byte)(rnd >>> 8), (byte)rnd});
        int n = data.length;
        bos.write(new byte[]{(byte)(n >>> 24), (byte)(n >>> 16), (byte)(n >>> 8), (byte)n});
        bos.write(data);
        // pad 到 16 字节对齐, 填充字节 0x41 ('A')
        while (bos.size() % 16 != 0) bos.write(0x41);

        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(deriveAes(master), "AES"), new IvParameterSpec(IV));
        byte[] enc = c.doFinal(bos.toByteArray());

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(deriveMac(master), "HmacSHA256"));
        byte[] tag = Arrays.copyOfRange(mac.doFinal(enc), 0, 16);

        byte[] out = new byte[enc.length + 16];
        System.arraycopy(enc, 0, out, 0, enc.length);
        System.arraycopy(tag, 0, out, enc.length, 16);
        return out;
    }

    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }

    static String hexStr(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("usage: key|dec|enc <pub> <auth> [in out] | decraw|encraw <hexkey> <in> <out>");
            return;
        }
        String cmd = args[0];
        byte[] master;
        if (cmd.equals("decraw") || cmd.equals("encraw")) {
            master = hex(args[1]);
        } else {
            master = masterKey(Files.readAllBytes(Paths.get(args[1])), Files.readAllBytes(Paths.get(args[2])));
        }
        if (cmd.equals("key")) {
            System.out.println("[+] master key = " + hexStr(master));
            return;
        }
        String inPath, outPath;
        if (cmd.equals("decraw") || cmd.equals("encraw")) { inPath = args[2]; outPath = args[3]; }
        else { inPath = args[3]; outPath = args[4]; }

        byte[] data = Files.readAllBytes(Paths.get(inPath));
        byte[] res = cmd.startsWith("dec") ? decrypt(master, data) : encrypt(master, data);
        Files.write(Paths.get(outPath), res);
        String head = hexStr(Arrays.copyOfRange(res, 0, Math.min(8, res.length)));
        System.out.println("[+] " + cmd + " " + data.length + " -> " + res.length + " bytes, head=" + head);
    }
}
