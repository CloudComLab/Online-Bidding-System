package utility;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Scott
 */
public class CryptoUtils {
    public static final Logger LOGGER;
    
    public static final Encoder BASE64_ENCODER;
    public static final Decoder BASE64_DECODER;
    
    static {
        LOGGER = Logger.getLogger(CryptoUtils.class.getName());
        
        BASE64_ENCODER = Base64.getEncoder();
        BASE64_DECODER = Base64.getDecoder();
    }
    
    public static byte[] shrinkByteArray(final byte[] input, int targetSize) {
        if (input.length < targetSize) {
            throw new IllegalArgumentException("input bytes should be bigger than output size");
        } else if (input.length == targetSize) {
            return input;
        }

        byte[] target = new byte[targetSize];
        int offset = input.length / targetSize;

        for (int i = 0; i < targetSize; i++) {
            for (int j = 0; j < offset; j++) {
                target[i] ^= input[i * offset + j];
            }
        }

        return target;
    }

    public static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public static String sha256(String msg) {
        try {
            return Utils.bytes2hex(sha256(msg.getBytes("utf-8")));
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    public static SecretKey str2key(String key, String algo) throws UnsupportedEncodingException {
        byte[] keyBytes = shrinkByteArray(sha256(key.getBytes("utf-8")), 32);

        return new SecretKeySpec(keyBytes, algo);
    }

    public static IvParameterSpec key2IV(String key) throws UnsupportedEncodingException {
        byte[] bytes = shrinkByteArray(sha256(key.getBytes("utf-8")), 16);
        
        return new IvParameterSpec(bytes);
    }

    public static String encrypt(String key, String plainData) {
        String encryptedText = null;
        
        try {
            Key secretKey = str2key(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, key2IV(key));

            byte[] bytes = cipher.doFinal(plainData.getBytes("utf-8"));

            encryptedText = BASE64_ENCODER.encodeToString(bytes);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | NoSuchPaddingException |
                 UnsupportedEncodingException | InvalidKeyException | BadPaddingException |
                 InvalidAlgorithmParameterException | IllegalArgumentException e) {
            e.printStackTrace();
        }
        
        return encryptedText;
    }
    
    public static String decrypt(String key, String encryptedData) {
        try {
            Key secretKey = str2key(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.DECRYPT_MODE, secretKey, key2IV(key));

            byte[] bytes = BASE64_DECODER.decode(encryptedData);

            bytes = cipher.doFinal(bytes);

            return new String(bytes, "utf-8");
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | NoSuchPaddingException |
                 UnsupportedEncodingException | InvalidKeyException | BadPaddingException |
                 InvalidAlgorithmParameterException | IllegalArgumentException e) {
            e.printStackTrace();
        }
        
        return null;
    }

    public static String hmacSHA256(SecretKey key, String data) {
        try {
            Mac hmacSHA256 = Mac.getInstance("HmacSHA256");

            hmacSHA256.init(key);

            byte[] bytes = hmacSHA256.doFinal(data.getBytes("utf-8"));

            return Utils.bytes2hex(bytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | UnsupportedEncodingException e) {
            e.printStackTrace();

            return null;
        }
    }

    public static String hmacSHA256(String key, String data) {
        try {
            return hmacSHA256(new SecretKeySpec(key.getBytes("utf-8"), "HmacSHA256"), data);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();

            return null;
        }
    }
    
    public static String encodeKey(Key key) {
        return BASE64_ENCODER.encodeToString(key.getEncoded());
    }
    
    public static PublicKey decodePublicKey(String publicKeyStr) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            byte[] pkBytes = BASE64_DECODER.decode(publicKeyStr);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pkBytes);
            
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }
        
        return null;
    }
    
    public static PrivateKey decodePrivateKey(String privateKeyStr) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            byte[] pkBytes = BASE64_DECODER.decode(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkBytes);
            
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }
        
        return null;
    }
}
