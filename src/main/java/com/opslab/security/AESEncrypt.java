package com.opslab.security;

import org.apache.commons.net.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

/**
 * @Description:说明
 * @Author:xgchen
 * @Date:2016-07-11 15:58
 * @Version:V0.0.1
 */
public class AESEncrypt {

    private static final String ALGORITHM = "AES";
    /**
     * "算法/模式/补码方式"
     */
    private static final String FULLALG  = "AES/CBC/PKCS5Padding";

    public static String generateAESKey() throws NoSuchAlgorithmException {
        //KeyGenerator提供对称密钥生成器的功能，支持各种算法
        KeyGenerator keygen = KeyGenerator.getInstance(ALGORITHM);
        //SecretKey负责保存对称密钥
        SecretKey deskey = keygen.generateKey();
        return new String(Base64.encodeBase64(deskey.getEncoded()));
    }
    
    /**
     * AES加密
     * @param content 待加密明文
     * @param key aes秘钥
     * @param charset 字符集
     * @return
     * @throws Exception
     */
    public static String encrypt(String content, String key, String charset) throws Exception {
        //反序列化AES密钥
        SecretKeySpec keySpec = new SecretKeySpec(Base64.decodeBase64(key.getBytes()), ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(initIv(FULLALG));
        //初始化加密器并加密
        Cipher cipher = Cipher.getInstance(FULLALG);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        byte[] encryptBytes = cipher.doFinal(content.getBytes(charset));
        return new String(Base64.encodeBase64(encryptBytes));
    }

    /**
     * AES解密
     * @param content 密文
     * @param key aes密钥
     * @param charset 字符集
     * @return 原文
     * @throws Exception
     */
    public static String decrypt(String content, String key, String charset) throws Exception {
        //反序列化AES密钥
        SecretKeySpec keySpec = new SecretKeySpec(Base64.decodeBase64(key.getBytes()), ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(initIv(FULLALG));
        //初始化加密器并加密
        Cipher deCipher = Cipher.getInstance(FULLALG);
        deCipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
        byte[] encryptedBytes = Base64.decodeBase64(content.getBytes(charset));
        byte[] bytes = deCipher.doFinal(encryptedBytes);
        return new String(bytes);
    }

    /**
     * 初始向量的方法, 全部为0. 这里的写法适合于其它算法,针对AES算法的话,IV值一定是128位的(16字节).
     * @param fullAlg
     * @return
     * @throws GeneralSecurityException
     */
    private static byte[] initIv(String fullAlg) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(fullAlg);
        int blockSize = cipher.getBlockSize();
        byte[] iv = new byte[blockSize];
        for (int i = 0; i < blockSize; ++i) {
            iv[i] = 0;
        }
        return iv;
    }
}
