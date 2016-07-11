package com.opslab.security;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @Description:RSA签名验签类
 * @Date:2016-07-11 11:33
 * @Version:V0.0.1
 */
public class RSASignature {

    /**
     * 签名算法
     */
    public static final String SIGN_ALGORITHMS = "SHA1WithRSA";
    private static final String ALGORITHM = "RSA";

    /**
     * RSA签名
     *
     * @param content    待签名数据
     * @param privateKey 私钥
     * @param encode     字符集编码
     * @return 签名值
     */
    public static String sign(String content, String privateKey, String encode) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKey));
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            PrivateKey priKey = factory.generatePrivate(keySpec);

            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);

            signature.initSign(priKey);
            signature.update(content.getBytes(encode));

            byte[] signed = signature.sign();
            return Base64.encode(signed);

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

    }

    /**
     * RSA验签
     *
     * @param content   待签名数据
     * @param publicKey 公钥
     * @param encode    字符集编码
     * @return 验签结果boolean
     */
    public static boolean verify(String content, String publicKey, String encode, String sign) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(publicKey));
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            PublicKey pubKey = factory.generatePublic(keySpec);

            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);

            signature.initVerify(pubKey);
            signature.update(content.getBytes(encode));

            return signature.verify(Base64.decode(sign));
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

    }
}
