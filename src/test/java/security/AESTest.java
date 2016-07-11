package security;

import com.opslab.security.AESEncrypt;
import com.sun.xml.internal.ws.api.ha.StickyFeature;
import junit.framework.TestCase;

import java.security.NoSuchAlgorithmException;

/**
 * @Description:说明
 * @Author:xgchen
 * @Date:2016-07-11 16:39
 * @Version:V0.0.1
 */
public class AESTest extends TestCase {
    String key = "R6XELoVCocjnrGkB8aIjvQ==";
    String content = "算法/模式/补码方式0102030405060708";
    String charset = "UTF-8";

    public void testGenerateKey() throws NoSuchAlgorithmException {
        System.out.println(AESEncrypt.generateAESKey());
    }

    public void testAesEncrypt() throws Exception {
        System.out.println(AESEncrypt.encrypt(content,key,charset));
    }

    public void testAesDecrypt() throws Exception {
        String mi = AESEncrypt.encrypt(content,key,charset);
        System.out.println("密文：" + mi);
        System.out.println("解密后"+AESEncrypt.decrypt(mi, key, charset));
    }
}
