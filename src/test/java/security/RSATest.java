package security;

import com.opslab.security.RSAEncrypt;
import com.opslab.security.RSAObtainKey;
import com.opslab.security.RSASignature;
import junit.framework.TestCase;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @Description:说明
 * @Date:2016-07-11 14:48
 * @Version:V0.0.1
 */
public class RSATest extends TestCase {

    String privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAN6S9bVg1RiX4UJpTrKDXYjJMuP/EKMY4VGUM7YoGNsHeD/XlOnrLUQ9KWycjhIfE+i3CzBrQKpB1CmwvATiF+F1GkcAJdVzAG1FvIbA15WoUkUyD7CDr5fZUv/RbNBbEffp8Dg9AsrZV6S1nF1z8OKoEo2fRIM2WCV9taoIS8EhAgMBAAECgYEAv7Wzf/wc8Gb5tptAFtDBwu0SMYHkUac/hGXzuKWG6zne4JaPBID1534K7StXz9IG8v6e26C1/TBgT1yURlx8FbFpWL+OKzPyjEy8osasM7egAFYCvqmpDK0ylrDpwt2Aknx7MnUYw7ZBg5v92HbOhUtxYZgNt6ecGVkOHSzkeZUCQQD7O777C++cUjXhuPnB4p+8xeXXw3vpRHaD8T0w1JFKrNq9Hp4sESi+Z6sH8pf79W8pBb3dC2QlTwuNzP974mmzAkEA4swDkI4KvpPpb6WILs1Lj6RWAFlKZsPvMn4OF9VLPCbf8BUAlH3XGO6PnCRjcLQZuYyh23frdLxPKPU5BtLX2wJBAJlnTOEb064+4Jm4igCicWkh6YtK2RGBdWBxYCy9zw2q6FGMLYa434kL4foTXkxB/CMvV1RujTLexi5Km0G46VMCQACRSiD+egBoFll1LJYRZXMCkkSF9K21J9AUiKx+mCWaY00SgGHevr8NOcbGQIlzqezQ8Ua/UhOEtR4BHxdpR6kCQQCshk2e9Y2NPAVipIeD16UVlSHLC3Xx5hszrLtiHk9yqtx4/RU7jNyBDv5it05ZQ18LA44Sqq4P6h4OXSqS9/6k";
    String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDekvW1YNUYl+FCaU6yg12IyTLj/xCjGOFRlDO2KBjbB3g/15Tp6y1EPSlsnI4SHxPotwswa0CqQdQpsLwE4hfhdRpHACXVcwBtRbyGwNeVqFJFMg+wg6+X2VL/0WzQWxH36fA4PQLK2VektZxdc/DiqBKNn0SDNlglfbWqCEvBIQIDAQAB";
    String content = "由于项目要用到非对称加密解密签名校验什么的，于是参考《Java加密解密的艺术》写一个RSA进行加密解密签名及校验的Demo，代码很简单，特此分享！";

    public void testPrivateKeyEncrypt() throws Exception {
        RSAPrivateKey priKey = RSAObtainKey.loadPrivateKeyByStr(privateKey);
        RSAPublicKey pubKey = RSAObtainKey.loadPublicKeyByStr(publicKey);
        String priResult = RSAEncrypt.encrypt(priKey, content.getBytes("UTF-8"));
        System.out.println("私钥加密结果：" + priResult);

        String pubDeResult = RSAEncrypt.decrypt(pubKey, priResult, "UTF-8");
        System.out.println("公钥解密结果：" + pubDeResult);
    }

    public void testPublickKeyEncrypt() throws Exception {
        RSAPrivateKey priKey = RSAObtainKey.loadPrivateKeyByStr(privateKey);
        RSAPublicKey pubKey = RSAObtainKey.loadPublicKeyByStr(publicKey);
        String pubResult = RSAEncrypt.encrypt(pubKey, content.getBytes("UTF-8"));
        System.out.println("公钥加密结果：" + pubResult);

        String priDeResult = RSAEncrypt.decrypt(priKey, pubResult, "UTF-8");
        System.out.println("私钥解密结果：" + priDeResult);
    }

    public void testVerify() {
        String singResult = RSASignature.sign(content, privateKey, "UTF-8");
        Boolean verify = RSASignature.verify(content, publicKey, "UTF-8", singResult);
        System.out.println("验签结果：" + verify);
    }
}
