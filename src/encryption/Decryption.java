package encryption;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import other.AlgorithmInfo;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Base64;

/**
 * Created on 17-Apr-17.
 */
public class Decryption extends EncDec {

    public static boolean saveDec(File fromFile, File toFile, String receiver, byte[] hashedPassword) throws
            GeneralSecurityException, IOException, InvalidCipherTextException {
        AlgorithmInfo info = AlgorithmInfo.generateInfo(fromFile);
        if (info == null)
            return false;
        String sessionKeyHashedStr = info.getReceiverKeyMap().get(receiver);

        Cipher rsaCipher = rsaPrivCipher(receiver, hashedPassword);
        BufferedBlockCipher aesCipher = aesCipher(sessionKeyHashedStr, info, rsaCipher, hashedPassword);

        FileInputStream fis = new FileInputStream(fromFile);
        fis.skip(info.getHeaderEnd());

//        final String extension = getExtension(fromFile);
//        final String toExtension = getExtension(toFile);
        FileOutputStream fos = new FileOutputStream(toFile.getPath()/* + (toExtension.isEmpty() ? extension : "")*/);

        int noBytesRead;        //number of bytes read from input
        int noBytesProcessed;   //number of bytes processed
        byte[] buf = new byte[aesCipher.getBlockSize()];
        byte[] obuf = new byte[aesCipher.getBlockSize() + aesCipher.getOutputSize(buf.length)];

        while ((noBytesRead = fis.read(buf)) > 0) {
            noBytesProcessed = aesCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
            fos.write(obuf, 0, noBytesProcessed);
        }

        noBytesProcessed = aesCipher.doFinal(obuf, 0);
        fos.write(obuf, 0, noBytesProcessed);
        fos.flush();

        fis.close();
        fos.close();
        return true;
    }

    /**
     * Decodes private key using password and creates a cipher that is using receiver's private key.
     */
    private static Cipher rsaPrivCipher(String receiver, byte[] hashedPassword) throws GeneralSecurityException, IOException {
        Key privKey = getPrivateKey(receiver, hashedPassword);
        if (privKey == null) //there's no such user or password is wrong
            return null;

        Cipher rsaPrivCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaPrivCipher.init(Cipher.DECRYPT_MODE, privKey);
        return rsaPrivCipher;
    }

    /**
     * Decodes session key using private key (rsaCipher) and creates an aes cipher to decode file.
     */
    private static BufferedBlockCipher aesCipher(String sessionKeyHashedStr, AlgorithmInfo info, Cipher rsaCipher, byte[] hashedPassword)
            throws GeneralSecurityException {
        byte[] keyByte;
        boolean wrongPassword;
        if (rsaCipher == null) { //there's no such user or password is wrong
            keyByte = EncDec.makeHashedPasswordNBytes(hashedPassword, info.getKeySize() / 8);
            wrongPassword = true;
        } else {
            final byte[] sessionKeyDecoded = Base64.getDecoder().decode(sessionKeyHashedStr);
            keyByte = rsaCipher.doFinal(sessionKeyDecoded);
            wrongPassword = false;
        }

        return EncDec.getBufferedBlockCipher(keyByte, false, info, wrongPassword);
    }


}
