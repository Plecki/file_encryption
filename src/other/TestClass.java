package other;

import encryption.Decryption;
import encryption.EncDec;
import encryption.Encryption;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Created on 21-May-17.
 */
public class TestClass {
    static File fromFile = new File("C:/Users/Piotr/Desktop/quote.txt");
    static String extension = ".txt";
    static String testDir = "test results";

    @BeforeClass
    public static void removeCryptographyRestrictions() {
        Main.removeCryptographyRestrictions();
        new File(testDir).mkdir();
    }

    @Test
    public void symmetricKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        int keySize = 256;
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(System.currentTimeMillis());
        keyGen.init(keySize, new SecureRandom(buffer.array()));
        Key symmetricKey = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/" + "CBC" + "/PKCS5Padding");

        IvParameterSpec iv = new IvParameterSpec(new SecureRandom().generateSeed(16));
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, iv);
    }

    private File encrypt(String desktopPath, int keySize, int blockSize, String mode, AlgorithmInfo info, File
            fromFile, String encryptFolderName) throws GeneralSecurityException, IOException, InvalidCipherTextException {
        final File encryptFolder = new File(desktopPath, encryptFolderName);
        if (!encryptFolder.exists())
            encryptFolder.mkdir();
        final File encryptedFile = new File(encryptFolder, mode + "k" + keySize + "b" + blockSize +
                "sb" + info.getSubblockSize());

        Encryption.saveEnc(fromFile, encryptedFile, info);
        return encryptedFile;
    }

    private File decrypt(String directoryPath, int keySize, int blockSize, String mode, File encryptedFile,
            int subblockSize, String decryptFolderName) throws GeneralSecurityException, IOException,
            InvalidCipherTextException {
        final File decryptFolder = new File(directoryPath, decryptFolderName);
        if (!decryptFolder.exists())
            decryptFolder.mkdir();
        final File decryptedFile = new File(decryptFolder, mode + "k" + keySize + "b" + blockSize +
                "sb" + subblockSize + extension);
        Decryption.saveDec(encryptedFile, decryptedFile, "1234", Encryption.hashPassword("1234"));
        return decryptedFile;
    }

    @Test
    public void encryptDecryptEverything() throws GeneralSecurityException, IOException, InvalidCipherTextException {
        List<String> receivers = new ArrayList<>();
        receivers.add("1234");
        String[] modes = {"ECB", "CBC", "CFB", "OFB"};

        for (int keySize = 128; keySize <= 256; keySize += 64) {
            for (int blockSize = 128; blockSize <= 256; blockSize += 64) {
                for (String mode : modes) {
                    final AlgorithmInfo info = new AlgorithmInfo(keySize, blockSize, 8, mode, receivers);
                    //info.setSubblockSize(8);
                    final File fromFile = TestClass.fromFile;
                    assert fromFile.exists();

                    //encryption
                    final File encryptedFile = encrypt(testDir, keySize, blockSize, mode, info, fromFile,
                            "encEvrthng");

                    //decryption
                    final File decryptedFile = decrypt(testDir, keySize, blockSize, mode, encryptedFile,
                            8, "decEvrthng");

                    BufferedReader fileReader1 = new BufferedReader(new FileReader(fromFile));
                    BufferedReader fileReader2 = new BufferedReader(new FileReader(decryptedFile));
                    String line1;
                    while ((line1 = fileReader1.readLine()) != null) {
                        assert (Objects.equals(line1, fileReader2.readLine()));
                    }
                    fileReader1.close();
                    fileReader2.close();
                }
            }
        }
    }

    private List<Integer> subblockSizeList(int blockSize) {
        List<Integer> ret = new ArrayList<>();
        //ret.add(2);
        //ret.add(4);
        for (int i = 8; i < blockSize; i += 8) {
            ret.add(i);
        }
        return ret;
    }

    @Test
    public void encDecCFBBlockSizes() throws GeneralSecurityException, IOException, InvalidCipherTextException {
        List<String> receivers = new ArrayList<>();
        receivers.add("1234");
        String[] modes = {"CFB", "OFB"};
        int keySize = 256, blockSize = 256;

        for(String mode : modes) {
            List<Integer> subblockSizes = subblockSizeList(blockSize);
            for (Integer subBlockSize : subblockSizes) {
                final AlgorithmInfo info = new AlgorithmInfo(keySize, blockSize, subBlockSize, mode, receivers);
                //info.setSubblockSize(subBlockSize);
                final File fromFile = TestClass.fromFile;
                assert fromFile.exists();

                // TODO: 31-May-17 tworzenie uzytkownika jesli nie istnieje, nie mozna zakladac ze bedzie 1234
                //encryption
                final File encryptedFile = encrypt(testDir, keySize, blockSize, mode, info, fromFile, "encCfbOfb");

                //decryption
                final File decryptedFile = decrypt(testDir, keySize, blockSize, mode, encryptedFile,
                        subBlockSize, "decCfbOfb");

                BufferedReader fileReader1 = new BufferedReader(new FileReader(fromFile));
                BufferedReader fileReader2 = new BufferedReader(new FileReader(decryptedFile));
                String line1;
                while ((line1 = fileReader1.readLine()) != null) {
                    assert (Objects.equals(line1, fileReader2.readLine()));
                }
            }
        }
    }

    @Test
    public void subblockLessThanByteCipher() throws GeneralSecurityException, IOException {
        List<String> receivers = new ArrayList<>();
        receivers.add("1234");
        final AlgorithmInfo info = new AlgorithmInfo(128, 128, 8, "CFB", receivers);
        //info.setIV();
        Key symmetricKey = Encryption.generateSymmetricKey(info);
        BufferedBlockCipher bbc = EncDec.getBufferedBlockCipher(symmetricKey.getEncoded(), true, info);
        bbc.getOutputSize(17);
    }

    @Test
    public void privateKeyWrong() throws GeneralSecurityException, IOException {
        EncDec.getPrivateKey("1234", Encryption.hashPassword("12345"));
    }

    // TODO: 25-May-17 testy z blednymi uzytkownikami - wystarczy encdeceverything i cfb bez asserta
    // TODO: 31-May-17 testy z blednymi plikami - bez naglowka, ze zlymi znacznikami, szyfrogramem itp

}
