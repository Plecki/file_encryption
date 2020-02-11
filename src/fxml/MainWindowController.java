package fxml;

import encryption.Decryption;
import encryption.EncDec;
import encryption.Encryption;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.Label;
import javafx.scene.control.Menu;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.bouncycastle.crypto.InvalidCipherTextException;
import other.AlgorithmInfo;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Objects;
import java.util.ResourceBundle;

public class MainWindowController implements Initializable {

    @FXML
    TextField fileEncPathText;

    @FXML
    TextField fileDecPathText;

    @FXML
    TextField fileEncPathOutText;

    @FXML
    TextField fileDecPathOutText;

    @FXML
    ChoiceBox<Integer> keySizeChoice;

    @FXML
    PasswordField passwordDecText;

    @FXML
    ChoiceBox<Integer> subblockSizeChoice;

    @FXML
    ListView<String> receiverView;

    @FXML
    ListView<String> usersView;

    @FXML
    ListView<String> usersFriendsView;

    @FXML
    ChoiceBox<String> modeChoice;

    @FXML
    ChoiceBox<Integer> blockSizeChoice;

    @FXML
    Label subblockSizeLabel;

    @FXML
    ListView<String> receiverChosenView;

    @FXML
    ListView<String> receiverDecView;

    @FXML
    ListView<String> errorView;


    ObservableList<Integer> subblockSizeObList = FXCollections.observableArrayList();
    ObservableList<String> receiverDecObList = FXCollections.observableArrayList();
    ObservableList<String> receiverObList = FXCollections.observableArrayList();
    ObservableList<String> receiverChosenObList = FXCollections.observableArrayList();
    ObservableList<String> usersObList = FXCollections.observableArrayList();
    ObservableList<String> usersFriendsObList = FXCollections.observableArrayList();
    ObservableList<String> errorObList = FXCollections.observableArrayList();
    private Stage stage;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        modeChoice.getSelectionModel().selectedIndexProperty().addListener(setModeChangeListener());
        blockSizeChoice.getSelectionModel().selectedIndexProperty().addListener(((observable, oldValue, newValue) -> {
            setSubblockSizeObList(blockSizeChoice.getItems().get(newValue.intValue()));
        }));
        setListViewItems();
        setChoiceBoxesItems();
        refreshUserLists();
    }

    private void setListViewItems() {
        receiverDecView.setItems(receiverDecObList);
        receiverView.setItems(receiverObList);
        receiverChosenView.setItems(receiverChosenObList);
        usersFriendsView.setItems(usersFriendsObList);
        usersView.setItems(usersObList);
        errorView.setItems(errorObList);
        errorObList.addListener((ListChangeListener<String>) c -> {
            c.next();
            if (c.wasAdded() && errorObList.size() > 4)
                errorObList.remove(4);
            errorView.requestLayout();
        });
        fileDecPathText.textProperty().addListener((observable) -> refreshReceiverList());
    }

    private ChangeListener<Number> setModeChangeListener() {
        return (observable, oldValue, newValue) -> {
            final Object selectedTryb = modeChoice.getItems().get(newValue.intValue());
            if (selectedTryb == "CFB" || selectedTryb == "OFB") {
                subblockSizeChoice.setVisible(true);
                subblockSizeLabel.setVisible(true);

                setSubblockSizeObList(blockSizeChoice.getSelectionModel().getSelectedItem());
            } else {
                subblockSizeChoice.setVisible(false);
                subblockSizeLabel.setVisible(false);
            }
        };
    }

    private void setSubblockSizeObList(int blockSize) {
        subblockSizeObList.clear();
        for (int i = 8; i < blockSize; i <<= 1) {
            subblockSizeObList.add(i);
        }
        subblockSizeChoice.getSelectionModel().select(0);
    }

    private void setChoiceBoxesItems() {
        modeChoice.setItems(FXCollections.observableArrayList("ECB", "CBC", "CFB", "OFB"));
        keySizeChoice.setItems(FXCollections.observableArrayList(128, 192, 256));
        blockSizeChoice.setItems(FXCollections.observableArrayList(128, 192, 256));
        subblockSizeChoice.setItems(subblockSizeObList);

        modeChoice.getSelectionModel().select(0);
        keySizeChoice.getSelectionModel().select(0);
        blockSizeChoice.getSelectionModel().select(0);
    }

    private void setReceivers(ObservableList<String> list, boolean publicKeys) {
        String directory = publicKeys ? EncDec.publicKeyDirectory : EncDec.privateKeyDirectory;
        File publicKeyDir = new File(directory);
        if (!publicKeyDir.exists()) {
            EncDec.createKeyDirectories();
            return;
        }

        list.clear();
        final File[] receiversFile = publicKeyDir.listFiles();
        if (receiversFile != null) {
            for (File receiver : receiversFile) {
                final String name = receiver.getName();
                final String extension = getExtension(name);
                list.add(name.substring(0, name.length() - extension.length()));
            }
        }
    }

    private static String getExtension(String fileName) {
        final int extensionBeginIndex = fileName.lastIndexOf('.');
        if (extensionBeginIndex <= 0)
            return "";
        else
            return fileName.substring(extensionBeginIndex);
    }

    private void refreshUserLists() {
        setReceivers(receiverObList, true);
        setReceivers(usersObList, false);
        setReceivers(usersFriendsObList, true);
    }

    @FXML
    void aboutAuthor() {
        JOptionPane.showMessageDialog(null, "Piotr Łęcki", "O autorze", JOptionPane
                .INFORMATION_MESSAGE);
    }

    @FXML
    void aboutProgram() {
        JOptionPane.showMessageDialog(null, "Program do szyfrowania i deszyfrowania wiadomości.", "O programie",
                JOptionPane.INFORMATION_MESSAGE);
    }

    @FXML
    void chooseOne() {
        String selected = receiverView.getSelectionModel().getSelectedItem();
        if (selected != null) {
            receiverObList.remove(selected);
            receiverChosenObList.add(selected);
        }
    }

    @FXML
    void removeOne() {
        String selected = receiverChosenView.getSelectionModel().getSelectedItem();
        if (selected != null) {
            receiverChosenObList.remove(selected);
            receiverObList.add(selected);
        }
    }

    @FXML
    void chooseAll() {
        for (String receiver : receiverObList) {
            receiverChosenObList.add(receiver);
        }
        receiverObList.clear();
    }

    @FXML
    void removeAll() {
        for (String receiver : receiverChosenObList) {
            receiverObList.add(receiver);
        }
        receiverChosenObList.clear();
    }

    @FXML
    void addFriend() throws IOException, GeneralSecurityException {
        final FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.home"), "Desktop"));
        File fromFile = fileChooser.showOpenDialog(stage);
        if (fromFile == null)
            return;

        File toFile = new File(EncDec.publicKeyDirectory, fromFile.getName());
        Files.copy(fromFile.toPath(), toFile.toPath());
        refreshUserLists();
    }

    @FXML
    void addUser() throws IOException, GeneralSecurityException {
        // TODO: 25-May-17 przycisk refresh uzytkownikow
        boolean added = addReceiver();
        if (added)
            errorObList.add(0, "Pomyslnie utworzono uzytkownika");
    }

    private boolean addReceiver() throws IOException, GeneralSecurityException {
        final FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("addReceiver.fxml"));
        final Parent root = fxmlLoader.load();
        AddReceiverController dialog = fxmlLoader.getController();
        String receiver = dialog.showWindow(stage, root);
        if (receiver != null) {
            final byte[] hashedPassword = dialog.getHashedPassword();
            EncDec.generateReceiver(receiver, hashedPassword);
            refreshUserLists();
            //listView.getItems().add(receiver);
            return true;
        } else {
            return false;
        }
    }

    private void chooseFile(TextField textField, boolean inFile) {
        final FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.home"), "Desktop"));
        File file;
        if (inFile)
            file = fileChooser.showOpenDialog(stage);
        else
            file = fileChooser.showSaveDialog(stage);
        if (file != null)
            textField.setText(file.getAbsolutePath());
    }

    @FXML
    void chooseFileEnc() {
        chooseFile(fileEncPathText, true);
    }

    @FXML
    void chooseFileEncOut() {
        chooseFile(fileEncPathOutText, false);
    }

    @FXML
    void saveEnc() {
        File fromFile = new File(fileEncPathText.getText());
        File toFile = new File(fileEncPathOutText.getText());

        if (!fromFile.exists()) {
            errorObList.add(0, "Plik wejsciowy nie istnieje.");
            return;
        }
        if (receiverChosenObList.isEmpty()) {
            errorObList.add(0, "Nie wybrano zadnego odbiorcy.");
            return;
        }
        if (toFile.getParent() == null || toFile.isDirectory()) {
            errorObList.add(0, "Nie mozna zapisac w tym miejscu.");
            return;
        }

        final AlgorithmInfo info = new AlgorithmInfo(keySizeChoice.getValue(), blockSizeChoice.getValue(),
                subblockSizeChoice.getValue(), modeChoice.getValue(), new ArrayList<>(receiverChosenObList));

        new Thread(() -> {
            try {
                Encryption.saveEnc(new File(fileEncPathText.getText()), toFile, info);
                Platform.runLater(() ->
                        errorObList.add(0, "Pomyslnie zaszyfrowano plik " + toFile.getName() + "."));
            } catch (IOException | GeneralSecurityException | InvalidCipherTextException e) {
                e.printStackTrace();
            }
        }).start();
    }

    @FXML
    void chooseFileDec() {
        chooseFile(fileDecPathText, true);
        refreshReceiverList();
    }

    private void refreshReceiverList() {
        // TODO: 25-May-17 kolorki kto moze odszyfrowac a kto nie
        receiverDecObList.clear();
        AlgorithmInfo info = AlgorithmInfo.generateInfo(new File(fileDecPathText.getText()));
        if (info != null) {
            Map<String, String> map = info.getReceiverKeyMap();
            for (String receiver : map.keySet()) {
                receiverDecObList.add(receiver);
            }
            receiverDecView.getSelectionModel().select(0);
        }
    }

    @FXML
    void chooseFileDecOut() {
        chooseFile(fileDecPathOutText, false);
    }

    @FXML
    void saveDec() throws GeneralSecurityException, IOException, InvalidCipherTextException {
        String receiver = receiverDecView.getSelectionModel().getSelectedItem();

        File fromFile = new File(fileDecPathText.getText());
        File toFile = new File(fileDecPathOutText.getText());
        if (!fromFile.exists()) {
            errorObList.add(0, "Plik wejsciowy nie istnieje.");
            return;
        }
        if (receiverDecView.getSelectionModel().isEmpty()) {
            errorObList.add(0, "Nie wybrano zadnego odbiorcy.");
            return;
        }
        if (Objects.equals(passwordDecText.getText(), "")) {
            errorObList.add(0, "Nie wpisano hasla.");
            return;
        }
        if (toFile.getParent() == null || toFile.isDirectory()) {
            errorObList.add(0, "Nie mozna zapisac w tym miejscu.");
            return;
        }

        final byte[] digestedPassword = Encryption.hashPassword(passwordDecText.getText());
        boolean saved = Decryption.saveDec(new File(fileDecPathText.getText()), toFile, receiver, digestedPassword);
        if (saved)
            errorObList.add(0, "Pomyslnie odszyfrowano plik " + toFile.getName() + ".");
        else
            errorObList.add(0, "Plik jest uszkodzony.");
    }

    public void setStage(Stage stage) {
        this.stage = stage;
    }

    public void showStage(Parent root) {
        stage.setTitle("Szyfrowanie Rijndael");
        Scene scene = new Scene(root);
        stage.setScene(scene);
        stage.setResizable(false);
        stage.show();
    }
}
