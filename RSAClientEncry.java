package zch.sugar.encryrsa;


import java.io.*;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 *
 * @author Sugar
 *
 * */

public class RSAClientEncry {

    private String crtPath = "C:/Users/Administrator/Desktop/sugar";
    private String crtType = "X.509";
    private BigInteger e;
    private BigInteger n;

    private RSAClientEncry() {
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
                BigInteger m = c.modPow(e, n);
                byte[] mB = m.toByteArray();
                offsetStream.write(mB.length - 512);
                byteArrayOutput.write(mB);
            }
            if (remainder != 0) {
                byteArray.read(byteremainder);
                BigInteger c = new BigInteger(byteremainder);
                BigInteger m = c.modPow(e, n);
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
                BigInteger m = c.modPow(e, n);
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

    public static RSAClientEncry getInstance(String crtPath, String crtType) throws CertificateException, IOException {
        RSAClientEncry rsaClientEncry = new RSAClientEncry();
        rsaClientEncry.crtPath = crtPath;
        rsaClientEncry.crtType = crtType;


        CertificateFactory certificateFactory = CertificateFactory.getInstance(rsaClientEncry.crtType);
        FileInputStream fileInputStream = new FileInputStream(rsaClientEncry.crtPath);
        Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
        RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();

        rsaClientEncry.e = publicKey.getPublicExponent();
        rsaClientEncry.n = publicKey.getModulus();

        fileInputStream.close();

        return rsaClientEncry;

    }

    public static RSAClientEncry getInstance(String crtPath) {
        RSAClientEncry rsaClientEncry = new RSAClientEncry();
        rsaClientEncry.crtPath = crtPath;

        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance(rsaClientEncry.crtType);
            FileInputStream fileInputStream = new FileInputStream(rsaClientEncry.crtPath);
            Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
            RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();

            rsaClientEncry.e = publicKey.getPublicExponent();
            rsaClientEncry.n = publicKey.getModulus();

            fileInputStream.close();
        } catch (Exception e) {
            throw new RuntimeException("certificate文件是否不存在或者文件路径不对", e);
        }

        return rsaClientEncry;
    }

}
