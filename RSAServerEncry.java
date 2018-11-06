package zch.sugar.encryrsa;



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;


/**
 *
 * @author Sugar
 *
 * */

public class RSAServerEncry {

    private String keyStorePath = "C:/Users/Administrator/Desktop/sugar.keystore";
    private String keyPass = "sugar123";
    private String crtPass = "sugar963";
    private String alias = "sugar";
    private String keyType = "JKS";
    private BigInteger d;
    private BigInteger n;

    private RSAServerEncry() {
    }

    public byte[][] encode(final byte[] cStr) {
        byte[] cStr64 = Base64.getEncoder().encode(cStr);
        ByteArrayOutputStream offsetStream = new ByteArrayOutputStream();
        byte[][] result = new byte[2][];
        int remainder = cStr64.length % 501;
        int quotient = cStr64.length / 501;
        byte[] byteremainder = new byte[remainder];
        ByteArrayOutputStream byteArrayOutput = new ByteArrayOutputStream();
        ByteArrayInputStream byteArray = new ByteArrayInputStream(cStr64);
        byte[] bytes = new byte[501];
        try {
            for (int i = 0; i < quotient; i++) {
                byteArray.read(bytes);
                BigInteger c = new BigInteger(bytes);
                BigInteger m = c.modPow(d, n);
                byte[] mB = m.toByteArray();
                offsetStream.write(mB.length - 512);
                byteArrayOutput.write(mB);
            }
            if (remainder != 0) {
                byteArray.read(byteremainder);
                BigInteger c = new BigInteger(byteremainder);
                BigInteger m = c.modPow(d, n);
                byte[] mB = m.toByteArray();
                offsetStream.write(mB.length - 512);
                byteArrayOutput.write(mB);
                byteArrayOutput.write(m.toByteArray());
            }
            result[0] = byteArrayOutput.toByteArray();
            result[1] = offsetStream.toByteArray();
            byteArray.close();
            byteArrayOutput.close();
            return result;
        } catch (IOException e) {
            throw new RuntimeException("流读取失败", e);
        }
    }

    public byte[] decode(byte[][] mStr) {
        byte[] result;
        byte[] ciphertext = mStr[0];
        byte[] offset = mStr[1];
        ByteArrayOutputStream byteArrayOutput = new ByteArrayOutputStream();
        ByteArrayInputStream byteArray = new ByteArrayInputStream(ciphertext);
        try {
            for (int i = 0; i < offset.length; i++) {
                int length = 512 + offset[i];
                byte[] bytes = new byte[length];
                byteArray.read(bytes);
                BigInteger c = new BigInteger(bytes);
                BigInteger m = c.modPow(d, n);
                byteArrayOutput.write(m.toByteArray());
            }
            result = Base64.getDecoder().decode(byteArrayOutput.toByteArray());
            byteArray.close();
            byteArrayOutput.close();
            return result;
        } catch (IOException e) {
            throw new RuntimeException("流读取失败", e);
        }

    }

    public static RSAServerEncry getInstance(String keyStorePath, String keyPass, String crtPass, String alias, String keyType) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        RSAServerEncry rsaServerEncry = new RSAServerEncry();
        rsaServerEncry.keyStorePath = keyStorePath;
        rsaServerEncry.keyPass = keyPass;
        rsaServerEncry.crtPass = crtPass;
        rsaServerEncry.alias = alias;
        rsaServerEncry.keyType = keyType;


        KeyStore keyStore = KeyStore.getInstance(rsaServerEncry.keyType);
        FileInputStream fileInputStream = new FileInputStream(rsaServerEncry.keyStorePath);
        keyStore.load(fileInputStream, rsaServerEncry.keyPass.toCharArray());
        RSAPrivateKey prk = (RSAPrivateKey) keyStore.getKey(rsaServerEncry.alias, rsaServerEncry.crtPass.toCharArray());

        rsaServerEncry.d = prk.getPrivateExponent();
        rsaServerEncry.n = prk.getModulus();

        fileInputStream.close();

        return rsaServerEncry;
    }

    public static RSAServerEncry getInstance(String keyStorePath) {
        RSAServerEncry rsaServerEncry = new RSAServerEncry();
        rsaServerEncry.keyStorePath = keyStorePath;

        try {
            KeyStore keyStore = KeyStore.getInstance(rsaServerEncry.keyType);
            FileInputStream fileInputStream = new FileInputStream(rsaServerEncry.keyStorePath);
            keyStore.load(fileInputStream, rsaServerEncry.keyPass.toCharArray());
            RSAPrivateKey prk = (RSAPrivateKey) keyStore.getKey(rsaServerEncry.alias, rsaServerEncry.crtPass.toCharArray());

            rsaServerEncry.d = prk.getPrivateExponent();
            rsaServerEncry.n = prk.getModulus();

            fileInputStream.close();
        } catch (Exception e) {
            throw new RuntimeException("keyStore文件是否不存在或者文件路径不对", e);
        }

        return rsaServerEncry;
    }
}
