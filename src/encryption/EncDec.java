package encryption;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.asymmetric.elgamal.CipherSpi;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import other.AlgorithmInfo;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Created on 18-Apr-17.
 */
public class EncDec {

    public static final String publicKeyDirectory = "keys/public";
    public static final String privateKeyDirectory = "keys/private";

    public static byte[] makeHashedPasswordNBytes(byte[] digestedPassword, int n) {
        byte ret[] = new byte[n];
        for (int i = 0; i < n; i += digestedPassword.length) {
            int length = (n - i >= digestedPassword.length) ? digestedPassword.length : n - i;
            System.arraycopy(digestedPassword, 0, ret, i, length);
        }
        return ret;
    }

    public static Key getPublicKey(String receiver) throws GeneralSecurityException, IOException {
        File receiverFile = EncDec.getReceiverPublicKeyFile(receiver);
        if (!receiverFile.exists())
            return null;

        PemReader pemReader = new PemReader(new FileReader(receiverFile));
        byte[] publicKeyHashedByte = pemReader.readPemObject().getContent();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final KeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyHashedByte);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static Key getPrivateKey(String receiver, byte[] hashedPassword) throws IOException, GeneralSecurityException {
        Key digestedPassKey = new SecretKeySpec(makeHashedPasswordNBytes(hashedPassword, 16), "AES");
        File receiverFile = EncDec.getReceiverPrivateKeyFile(receiver);
        if (!receiverFile.exists())
            return null;

        PemReader pemReader = new PemReader(new FileReader(receiverFile));
        byte[] privateKeyHashedByte = pemReader.readPemObject().getContent();

        Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
        aesCipher.init(Cipher.DECRYPT_MODE, digestedPassKey);
        byte[] privateKeyByte = aesCipher.doFinal(privateKeyHashedByte);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyByte);
        try {
            return keyFactory.generatePrivate(privateKeySpec);
        }
        catch (InvalidKeySpecException e) {
            return null;
        }
    }

    public static void generateReceiver(String receiver, byte[] digestedPassword) throws IOException, GeneralSecurityException {
        KeyPairGenerator keyPairGen = null;
        try {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert keyPairGen != null;
        KeyPair keyPair = keyPairGen.generateKeyPair();

        savePublicKey(receiver, keyPair.getPublic());
        savePrivateKey(receiver, keyPair.getPrivate(), digestedPassword);
    }

    private static void savePublicKey(String receiver, Key publicKey) throws FileNotFoundException {
        EncDec.createKeyDirectories();

        File pubKeyFile = EncDec.getReceiverPublicKeyFile(receiver);
//        String publicKeyStr = Base64.getEncoder().withoutPadding().encodeToString(publicKey.getEncoded());
        PemObject pemObject = new PemObject("RSA Public Key ", publicKey.getEncoded());
        try {
            OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(pubKeyFile));
            PemWriter pemWriter = new PemWriter(osw);
            pemWriter.writeObject(pemObject);
            //osw.write(publicKeyStr);
            pemWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void savePrivateKey(String receiver, Key privateKey, byte[] digestedPassword) throws GeneralSecurityException {
        EncDec.createKeyDirectories();

        Key digestedPassKey = new SecretKeySpec(EncDec.makeHashedPasswordNBytes(digestedPassword, 16), "AES");
        final String privKeyStr = Encryption.encryptKeyBase64(digestedPassKey, privateKey, "AES/ECB/PKCS5Padding");
        PemObject pemObject = new PemObject("RSA Private Key", Base64.getDecoder().decode(privKeyStr));

        File privKeyFile = EncDec.getReceiverPrivateKeyFile(receiver);
        try {
            OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(privKeyFile));
            PemWriter pemWriter = new PemWriter(osw);
            pemWriter.writeObject(pemObject);
//            osw.write(privKeyStr);
            pemWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static File getReceiverPublicKeyFile(String receiver) {
        return new File(publicKeyDirectory, receiver + ".pem");
    }

    public static File getReceiverPrivateKeyFile(String receiver) {
        // TODO: 25-May-17 przetestowac - plik istnieje, ale ma zla wartosc w srodku - ktos namieszal
        return new File(privateKeyDirectory, receiver + ".pem");
    }


    /**
     *
     */
    public static void createKeyDirectories() {
        File privDir = new File(privateKeyDirectory);
        privDir.mkdirs();
        File pubDir = new File(publicKeyDirectory);
        pubDir.mkdirs();

        if (!privDir.exists() || !pubDir.exists()) {
            try {
                throw new FileNotFoundException("Cannot find and/or create keys directory");
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    public static BufferedBlockCipher getBufferedBlockCipher(byte[] keyByte, boolean encrypt, AlgorithmInfo info) {
        return getBufferedBlockCipher(keyByte, encrypt, info, false);
    }

    public static BufferedBlockCipher getBufferedBlockCipher(byte[] keyByte, boolean encrypt, AlgorithmInfo info,
                                                             boolean wrongPassword) {
        BlockCipher engine = new RijndaelEngine(info.getBlockSize());
        BlockCipher blockCipher = null;
        switch (info.getMode()) {
            case "ECB" : blockCipher = engine; break;
            case "CBC" : blockCipher = new CBCBlockCipher(engine); break;
            case "CFB" : blockCipher = new CFBBlockCipher(engine, info.getSubblockSize()); break;
            case "OFB" : blockCipher = new OFBBlockCipher(engine, info.getSubblockSize()); break;
        }
        assert blockCipher != null;
        final PaddedBufferedBlockCipher cipher;

        BlockCipherPadding padding = wrongPassword ? new ZeroBytePadding() : new PKCS7Padding();

        if(Objects.equals(info.getMode(), "ECB")) {
            cipher = new PaddedBufferedBlockCipher(blockCipher, padding);
            cipher.init(encrypt, new KeyParameter(keyByte));
        }
        else {
            cipher = new PaddedBufferedBlockCipher(blockCipher, padding);
            cipher.init(encrypt, new ParametersWithIV(new KeyParameter(keyByte), info.getIV()));
        }

        return cipher;
    }
}
