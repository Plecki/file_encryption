package encryption;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import other.AlgorithmInfo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Base64;
import java.util.Objects;

/**
 * Created on 17-Apr-17.
 */
public class Encryption extends EncDec {

    public static void saveEnc(File fromFile, File toFile, AlgorithmInfo info) throws GeneralSecurityException,
            IOException, InvalidCipherTextException {

        if(!Objects.equals(info.getMode(), "ECB")) {
            final byte[] ivBytes = new SecureRandom().generateSeed(info.getBlockSize() / 8);
            info.setIV(ivBytes);
        }

        Key symmetricKey = generateSymmetricKey(info);
        BufferedBlockCipher symmetricCipher = EncDec.getBufferedBlockCipher(symmetricKey.getEncoded(), true, info);

        info.setSessionKeys(symmetricKey);

        FileInputStream fis = new FileInputStream(fromFile);
//        final String extension = EncDec.getExtension(fromFile);
//        final String toExtension = EncDec.getExtension(toFile);
        FileOutputStream fos = new FileOutputStream(toFile.getPath()/* + (toExtension.isEmpty() ? extension : "")*/);
        info.writeHeader(fos);

        int noBytesRead;        //number of bytes read from input
        int noBytesProcessed;   //number of bytes processed
        byte[] buf = new byte[16];
        byte[] obuf = new byte[symmetricCipher.getBlockSize() + symmetricCipher.getOutputSize(buf.length)];

        while ((noBytesRead = fis.read(buf)) > 0) {
            noBytesProcessed = symmetricCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
            fos.write(obuf, 0, noBytesProcessed);
        }

        noBytesProcessed = symmetricCipher.doFinal(obuf, 0);
        fos.write(obuf, 0, noBytesProcessed);
        fos.flush();

        fis.close();
        fos.close();
    }

    public static Key generateSymmetricKey(AlgorithmInfo info) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(System.currentTimeMillis());
        keyGen.init(info.getKeySize(), new SecureRandom(buffer.array()));
        return keyGen.generateKey();
    }

    public static String encryptKeyBase64(Key encryptionKey, Key encryptedKey, String algorithm) throws
            GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        final byte[] encryptedKeyEncoded = encryptedKey.getEncoded();
        final byte[] encryptedKeyByte = cipher.doFinal(encryptedKeyEncoded);
        return Base64.getEncoder().withoutPadding().encodeToString(encryptedKeyByte);
    }

    public static byte[] hashPassword(String password) {
        byte ret[] = null;
        try {
            MessageDigest crypt = MessageDigest.getInstance("SHA-256");
            crypt.update(password.getBytes());
            ret = crypt.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (ret == null)
            throw new IllegalStateException("Cannot digest password");
        return ret;
    }
}
