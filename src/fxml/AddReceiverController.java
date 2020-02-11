package fxml;

import java.net.URL;
import java.util.Objects;
import java.util.ResourceBundle;

import encryption.Encryption;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Modality;
import javafx.stage.Stage;

/**
 * FXML MainWindowController class
 */
public class AddReceiverController implements Initializable {

    @FXML
    private PasswordField passwordPass;

    @FXML
    private PasswordField passwordRepeatPass;

    @FXML
    private TextField nameText;

    private Stage stage;
    private String result;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
    }

    @FXML
    void save(ActionEvent event) {
        // TODO: 28-Mar-17 jesli jest taki odbiorca to blad, jesli haslo sie zgadza (np. liczba znakow)
        // obrazki i niezamykanie okna jesli nie sa takie same
        String wpisany = nameText.getText();
        if(!wpisany.isEmpty() && Objects.equals(passwordPass.getText(), passwordRepeatPass.getText())) {
            result = wpisany;
            stage.hide();
        }
    }

    @FXML
    void cancel(ActionEvent event) {
        result = null;
        stage.hide();
    }

    public String showWindow(Stage parentStage, Parent root) {
        stage = new Stage();
        stage.initOwner(parentStage);
        stage.setTitle("Dodaj odbiorcę");
        stage.setScene(new Scene(root, 257, 161));
        stage.setResizable(false);
        stage.initModality(Modality.APPLICATION_MODAL);
        stage.showAndWait();

        return result;
    }

    public byte[] getHashedPassword() {
        return Encryption.hashPassword(passwordPass.getText());
    }
}