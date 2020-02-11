package other;

import encryption.EncDec;
import encryption.Encryption;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.*;

/**
 * Created on 18-Apr-17.
 */
public class AlgorithmInfo {
    final static String xmlEndingStr = "</EncryptedFileHeader>";

    private int headerEnd = -1;
    private int keySize;
    private int blockSize;
    private String mode;
    private byte[] IV = new byte[]{};
    private Map<String, String> receiverKeyMap;
    private Integer subblockSize;

    public AlgorithmInfo(int keySize, int blockSize, int subblockSize, String mode, List<String> receivers) {
        this(keySize, blockSize, mode, receivers);
        this.subblockSize = subblockSize;
    }

    public AlgorithmInfo(int keySize, int blockSize, String mode, List<String> receivers) {
        this.keySize = keySize;
        this.blockSize = blockSize;
        this.mode = mode;
        receiverKeyMap = new TreeMap<>();
        if (receivers != null) {
            for (String receiver : receivers) {
                receiverKeyMap.put(receiver, null);
            }
        }
    }

    private void addXmlChild(Document doc, Element parent, String name, String value) {
        final Element element = doc.createElement(name);
        element.appendChild(doc.createTextNode(value));
        parent.appendChild(element);
    }

    public void writeHeader(FileOutputStream fos) throws IOException {
        OutputStreamWriter osw = new OutputStreamWriter(fos);
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.newDocument();

            final Element fileHeader = doc.createElement("EncryptedFileHeader");
            doc.appendChild(fileHeader);

            addXmlChild(doc, fileHeader, "Algorithm", "Rijndael");
            addXmlChild(doc, fileHeader, "KeySize", Integer.toString(keySize));
            addXmlChild(doc, fileHeader, "BlockSize", Integer.toString(blockSize));
            if(subblockSize != null)
                addXmlChild(doc, fileHeader, "SubBlockSize", Integer.toString(subblockSize));
            addXmlChild(doc, fileHeader, "CipherMode", mode);
            addXmlChild(doc, fileHeader, "IV", Base64.getEncoder().withoutPadding().encodeToString(IV));

            final Element approvedUsers = doc.createElement("ApprovedUsers");
            fileHeader.appendChild(approvedUsers);

            for (Map.Entry<String, String> pair : receiverKeyMap.entrySet()) {
                final Element user = doc.createElement("User");
                approvedUsers.appendChild(user);

                addXmlChild(doc, user, "Email", pair.getKey());
                addXmlChild(doc, user, "SessionKey", pair.getValue());
            }

            DOMSource source = new DOMSource(doc);
            StreamResult sr = new StreamResult(osw);
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            transformer.transform(source, sr);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static AlgorithmInfo generateInfo(File fromFile) {
        AlgorithmInfo info = null;
        try {
            if(!fromFile.canRead())
                return null;
            //sb bedzie Stringiem calego pliku wczytywanego
            StringBuilder sb = new StringBuilder();
            BufferedReader br = new BufferedReader(new FileReader(fromFile));
            String line;
            //czytam linia po linii i zapisuje do StringBuildera az natrafie na String konczacy xmla
            do {
                line = br.readLine();
                sb.append(line).append("  "); //" " is for every return
            }
            while (line!=null && !line.contains(xmlEndingStr));

            if(line == null) //there's no header
                return null;


            //headerEnd to numer bajtu konczacego xmla (naglowek)
            int headerEnd = sb.lastIndexOf(xmlEndingStr) + xmlEndingStr.length();
            //caly naglowek jest zapisywany do xmlHeader
            String xmlHeader = sb.substring(0, headerEnd);
            if(line.endsWith(xmlEndingStr))
                headerEnd += 2;

            //klasy czytajace i parsujace XMLa, w konstruktorze jest sztuczny InputStream bioracy bajty ze Stringa, a
            // nie z pliku - tutaj bedzie tylko naglowek xmlowy
            DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new ByteArrayInputStream(xmlHeader.getBytes("utf-8"))));

            // TODO: 31-May-17 sprawdzanie czy nazwa algorytmu sie zgadza
            //wyciąganie informacji z xmla az do konca funkcji
            int keysize = Integer.parseInt(doc.getElementsByTagName("KeySize").item(0).getTextContent());
            int blocksize = Integer.parseInt(doc.getElementsByTagName("BlockSize").item(0).getTextContent());
            String mode = doc.getElementsByTagName("CipherMode").item(0).getTextContent();
            final NodeList subBlockSize = doc.getElementsByTagName("SubBlockSize");
            if(subBlockSize.getLength() != 0) {
                int subblocksize = Integer.parseInt(subBlockSize.item(0).getTextContent());
                info = new AlgorithmInfo(keysize, blocksize, subblocksize, mode, null);
            }
            else
                info = new AlgorithmInfo(keysize, blocksize, mode, null);
            info.setHeaderEnd(headerEnd);

            final Node ivNode = doc.getElementsByTagName("IV").item(0);
            if (ivNode.hasChildNodes()) {
                byte[] iv = Base64.getDecoder().decode(ivNode.getTextContent().getBytes());
                info.setIV(iv);
            }

            NodeList users = doc.getElementsByTagName("ApprovedUsers").item(0).getChildNodes();
            Map<String, String> receiverKeyMap = new HashMap<>();
            for (int i = 0; i < users.getLength(); i++) {
                if(Objects.equals(users.item(i).getNodeName(), "User")) {
                    final Element item = (Element) (users.item(i));
                    final String email = item.getElementsByTagName("Email").item(0).getTextContent();
                    final String sessionKey = item.getElementsByTagName("SessionKey").item(0).getTextContent();
                    receiverKeyMap.put(email, sessionKey);
                }
            }
            info.setReceiverKeyMap(receiverKeyMap);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return info;
    }

    public void setSessionKeys(Key symmetricKey) throws GeneralSecurityException, IOException {
        for (Map.Entry<String, String> pair : receiverKeyMap.entrySet()) {
            final String receiverName = pair.getKey();
            Key publicKey = EncDec.getPublicKey(receiverName);
            String sessionKey;
            if (publicKey == null) sessionKey = null;
            else sessionKey = Encryption.encryptKeyBase64(publicKey, symmetricKey, "RSA/ECB/PKCS1Padding");
            receiverKeyMap.replace(receiverName, sessionKey);
        }
    }

    public int getHeaderEnd() {
        return headerEnd;
    }

    public int getKeySize() {
        return keySize;
    }

    public int getBlockSize() {
        return blockSize;
    }

    public String getMode() {
        return mode;
    }

    public byte[] getIV() {
        return IV;
    }

    public Map<String, String> getReceiverKeyMap() {
        return receiverKeyMap;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public void setBlockSize(int blockSize) {
        this.blockSize = blockSize;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public void setIV(byte[] IV) {
        this.IV = IV;
    }

    public void setReceiverKeyMap(Map<String, String> receiverKeyMap) {
        this.receiverKeyMap = receiverKeyMap;
    }

    private void setHeaderEnd(int headerEnd) {
        this.headerEnd = headerEnd;
    }

    public void setSubblockSize(Integer subblockSize) {
        this.subblockSize = subblockSize;
    }

    public Integer getSubblockSize() {
        return subblockSize;
    }
}
