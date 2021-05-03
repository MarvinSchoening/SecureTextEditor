package editor;

import java.nio.charset.StandardCharsets;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.layout.GridPane;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class OptionsPage {

  private String encryptionType;
  private String blockmode;
  private String padding;
  private String keySize;
  private String hashOrMac;
  private String save;
  private String title;
  private String message;
  private String password;

  private ObservableList<String> encryptionTypeList;
  private ObservableList<String> blockmodeListAes;
  private ObservableList<String> blockmodeListDes;
  private ObservableList<String> paddingList;
  private ObservableList<String> keysizeListAes;
  private ObservableList<String> hashOrMacList;
  private ObservableList<String> typeList;
  private ObservableList<String> passwordEncryptionTypeList;

  private ComboBox<String> encryptionTypeBox = new ComboBox<>();
  private ComboBox<String> blockmodeBox = new ComboBox<>();
  private ComboBox<String> paddingBox = new ComboBox<>();
  private ComboBox<String> keySizeBox = new ComboBox<>();
  private ComboBox<String> hashOrMacBox = new ComboBox<>();
  private ComboBox<String> typeSelectionBox = new ComboBox<>();

  private PasswordField passwordInputField = new PasswordField();

  private Label description = new Label();
  private Label encryptionTypeLabel = new Label();
  private Label blockmodeLabel = new Label();
  private Label paddingLabel = new Label();
  private Label keySizeLabel = new Label();
  private Label hashOrMacLabel = new Label();
  private Label passwordLabel = new Label();
  private Label typeLabel = new Label();

  private Button saveButton;

  private Stage window;
  private GridPane grid;
  private Scene scene;
  private Group root;

  /**
   * Option Window to select encryption Options.
   *
   * @param input Input from TextArea to check byte length for blockmode/padding
   */
  public OptionsPage(String input) {
    saveButton = new Button("Speichern");
    this.title = "Einstellungen";
    this.message = "Bitte wähle deine Einstellungen";
    this.save = "false";
    this.description.setText(message);

    grid = new GridPane();

    scene = new Scene(new Group(), 650, 450);

    window = new Stage();
    window.initModality(Modality.APPLICATION_MODAL);
    window.setTitle(title);
    window.setMinHeight(250);

    root = (Group) scene.getRoot();

    typeList = FXCollections.observableArrayList("Ohne Passwort", "Mit Passwort");
    encryptionTypeList = FXCollections.observableArrayList("AES", "DES");
    passwordEncryptionTypeList = FXCollections.observableArrayList(
            "AES256, GCM, SCrypt", "PBEWithSHA256And128BitAES-CBC-BC", "PBEWithSHAAnd40BitRC4");

    if (input.getBytes(StandardCharsets.UTF_8).length < 16) {
      blockmodeListAes = FXCollections.observableArrayList("ECB", "CBC", "CTR", "CFB", "GCM", "CCM");
      blockmodeListDes = FXCollections.observableArrayList("ECB", "CBC", "CTR", "CFB");
      paddingList = FXCollections.observableArrayList("ZeroBytePadding", "PKCS7Padding");
    } else {
      blockmodeListAes = FXCollections.observableArrayList(
              "ECB", "CBC", "CTR", "CFB", "OFB", "GCM", "CCM"
      );
      blockmodeListDes = FXCollections.observableArrayList("ECB", "CBC", "CTR", "CFB", "OFB");
      paddingList = FXCollections.observableArrayList(
              "ZeroBytePadding",
              "PKCS7Padding",
              "CTSPadding");
    }

    hashOrMacList = FXCollections.observableArrayList("SHA-256", "AESCMAC", "HmacSHA256");
    keysizeListAes = FXCollections.observableArrayList("128", "192", "256");
    typeSelectionBox.setItems(typeList);
  }

  private void setLabels() {
    encryptionTypeLabel.setText("Text Verschlüsselung");
    blockmodeLabel.setText("Blockmodus");
    paddingLabel.setText("Padding");
    keySizeLabel.setText("Schlüsselgröße");
    hashOrMacLabel.setText("Verifizierung");
    passwordLabel.setText("Passwort");
    typeLabel.setText("Verschlüsselungsmodus");
  }

  /*
  Hash or Mac
   */
  private void addHashOrMac(int column, int row) {
    grid.add(hashOrMacLabel, column, row);
    grid.add(hashOrMacBox, column + 1, row);
  }

  private void removeHashOrMac() {
    grid.getChildren().remove(hashOrMacLabel);
    grid.getChildren().remove(hashOrMacBox);
  }

  private void disableHashOrMac() {
    hashOrMacBox.setValue(null);
    hashOrMacBox.setVisible(false);
    hashOrMacLabel.setVisible(false);
  }

  private void enableHashOrMac() {
    hashOrMacBox.setValue(null);
    hashOrMacBox.setItems(hashOrMacList);
    hashOrMacBox.setVisible(true);
    hashOrMacLabel.setVisible(true);
  }

  private void setHashOrMacValue(String name) {
    hashOrMacBox.setValue(name);
  }

  /*
  KeySize
   */
  private void addKeySize(int column, int row) {
    grid.add(keySizeLabel, column, row);
    grid.add(keySizeBox, column + 1, row);
  }

  private void removeKeySize() {
    grid.getChildren().remove(keySizeLabel);
    grid.getChildren().remove(keySizeBox);
  }

  private void disableKeySize() {
    keySizeBox.setValue(null);
    keySizeBox.setVisible(false);
    keySizeLabel.setVisible(false);
  }

  private void enableKeySize() {
    keySizeBox.setValue(null);
    keySizeBox.setItems(keysizeListAes);
    keySizeBox.setVisible(true);
    keySizeLabel.setVisible(true);
  }

  private void setKeySizeValue(String size) {
    keySizeBox.setValue(size);
  }

  /*
  Blockmode
   */

  private void addBlockmode(int column, int row) {
    grid.add(blockmodeLabel, column, row);
    grid.add(blockmodeBox, column + 1, row);
  }

  private void removeBlockmode() {
    grid.getChildren().remove(blockmodeLabel);
    grid.getChildren().remove(blockmodeBox);
  }

  private void disableBlockmode() {
    blockmodeBox.setValue(null);
    blockmodeBox.setVisible(false);
    blockmodeLabel.setVisible(false);
  }

  private void enableBlockmode(ObservableList<String> list) {
    blockmodeBox.setValue(null);
    blockmodeBox.setItems(list);
    blockmodeBox.setVisible(true);
    blockmodeLabel.setVisible(true);
  }

  /*
  Padding
   */

  private void addPadding(int column, int row) {
    grid.add(paddingLabel, column, row);
    grid.add(paddingBox, column + 1, row);
  }

  private void removePadding() {
    grid.getChildren().remove(paddingLabel);
    grid.getChildren().remove(paddingBox);
  }

  private void disablePadding() {
    paddingBox.setValue(null);
    paddingBox.setVisible(false);
    paddingLabel.setVisible(false);
  }

  private void enablePadding() {
    paddingBox.setValue(null);
    paddingBox.setItems(paddingList);
    paddingBox.setVisible(true);
    paddingLabel.setVisible(true);
  }

  private void setPaddingValue(String padding) {
    paddingBox.setValue(padding);
    paddingBox.setVisible(false);
    paddingLabel.setVisible(false);
  }

  /*
  Password
   */
  private void addPassword(int column, int row) {
    grid.add(passwordLabel, column, row);
    grid.add(passwordInputField, column + 1, row);
  }

  private void removePassword() {
    grid.getChildren().remove(passwordLabel);
    grid.getChildren().remove(passwordInputField);
  }

  private void disablePassword() {
    passwordLabel.setVisible(false);
    passwordInputField.setVisible(false);
  }

  private void enablePassword() {
    passwordInputField.setVisible(true);
    passwordLabel.setVisible(true);
  }

  /*
  Save
   */
  private void addSave(int column, int row) {
    grid.add(saveButton, column, row);
  }

  private void removeSave() {
    grid.getChildren().remove(saveButton);
  }

  private void disableSaveButton() {
    saveButton.setVisible(false);
  }

  private void enableSaveButton() {
    saveButton.setVisible(true);
  }

  /*
  Encryption Type
   */

  private void addEncryptionType(int column, int row) {
    grid.add(encryptionTypeLabel, column, row);
    grid.add(encryptionTypeBox, column + 1, row);
  }

  private void removeEncryptionType() {
    grid.getChildren().remove(encryptionTypeBox);
    grid.getChildren().remove(encryptionTypeLabel);
  }

  private void disableEncryptionType() {
    encryptionTypeBox.setVisible(false);
    encryptionTypeLabel.setVisible(false);
  }

  private void enableEncryptionType(ObservableList<String> list) {
    encryptionTypeBox.setItems(list);
    encryptionTypeBox.setVisible(true);
    encryptionTypeLabel.setVisible(true);
  }


  /*
  Grid Operations
   */


  private void createGrid() {
    grid.setVgap(4);
    grid.setHgap(10);

    grid.setPadding(new Insets(5));
    grid.add(description, 1, 0);

    grid.add(typeLabel, 1, 1);
    grid.add(typeSelectionBox, 2, 1);
  }

  private void clearGrid() {
    removeKeySize();
    keySizeBox.setValue("");
    removeBlockmode();
    blockmodeBox.setValue("");
    removePadding();
    paddingBox.setValue("");
    removeHashOrMac();
    hashOrMacBox.setValue("");
    removeSave();
    removePassword();
    passwordInputField.textProperty().setValue("");
    removeEncryptionType();
    encryptionTypeBox.setValue("");

  }

  private void clearGridEncryptionType() {
    removeKeySize();
    removeBlockmode();
    removePadding();
    removeHashOrMac();
    removeSave();
  }

  private void clearForm() {
    //Alles Unsichtbar machen, bis ein encryptionTyp ausgewählt ist
    disableBlockmode();
    disablePadding();
    disableKeySize();
    disableHashOrMac();
    disableSaveButton();
    disablePassword();
    disableEncryptionType();
  }

  /*
  Encryption Types
   */

  private void aesSelected() {
    clearGridEncryptionType();
    addKeySize(1, 5);
    addHashOrMac(1, 6);
    addBlockmode(1, 7);
    addPadding(1, 8);
    addSave(1, 9);

    enableHashOrMac();
    enableBlockmode(blockmodeListAes);
    enableKeySize();
    disablePadding();

    setHashOrMacValue("SHA-256");
    setKeySizeValue("128");
  }

  private void desSelected() {
    clearGridEncryptionType();
    addHashOrMac(1, 5);
    addBlockmode(1, 6);
    addPadding(1, 7);
    addSave(1, 8);

    enableBlockmode(blockmodeListDes);
    enableHashOrMac();
    disablePadding();

    disableKeySize();
    setHashOrMacValue("SHA-256");
    setKeySizeValue("64");
  }

  private void withPassword() {
    clearGrid();
    enablePassword();
    addEncryptionType(1, 2);
    addPassword(1, 3);
    addHashOrMac(1, 4);
    addSave(1,5);

    enableHashOrMac();
    disableSaveButton();
    disablePassword();
    enableEncryptionType(passwordEncryptionTypeList);

    setHashOrMacValue("SHA-256");
  }

  private void withoutPassword() {
    clearGrid();
    addEncryptionType(1, 2);
    enableEncryptionType(encryptionTypeList);
  }

  /*
  Listener, Actions, Return Params
   */
  private void saveParams() {

    encryptionType = encryptionTypeBox.getSelectionModel().getSelectedItem();
    blockmode = blockmodeBox.getSelectionModel().getSelectedItem();
    padding = paddingBox.getSelectionModel().getSelectedItem();
    keySize = keySizeBox.getSelectionModel().getSelectedItem();
    hashOrMac = hashOrMacBox.getSelectionModel().getSelectedItem();
    password = passwordInputField.getText();
    save = "true";
  }

  private void initializeListeners() {
    typeSelectionBox.valueProperty().addListener((obs, oldValue, newValue) -> {
      if (newValue == null) {
        clearForm();
      } else if (newValue.equals("Mit Passwort")) {
        clearForm();
        withPassword();
      } else if (newValue.equals("Ohne Passwort")) {
        clearForm();
        withoutPassword();
        disablePassword();
      }
    });

    passwordInputField.textProperty().addListener((obs, oldValue, newValue) -> {
      if (newValue == null || newValue.equals("")) {
        disableSaveButton();
      } else {
        enableSaveButton();
      }
    });

    encryptionTypeBox.valueProperty().addListener((obs, oldValue, newValue) -> {
      if (newValue == null) {
        if (typeSelectionBox.getSelectionModel().getSelectedItem().equals("Ohne Passwort")
                || typeSelectionBox.getSelectionModel().getSelectedItem().equals("Mit Passwort")) {
          clearForm();
        }
      } else if (newValue.equals("AES")) {
        aesSelected();
      } else if (newValue.equals("DES")) {
        desSelected();
      } else if (!newValue.equals("")) {
        enablePassword();
      }
    });

    blockmodeBox.valueProperty().addListener((obs, oldValue, newValue) -> {
      if (newValue == null) {
        disablePadding();
      } else if (newValue.equals("ECB") || newValue.equals("CBC")) {
        enablePadding();
      } else {
        setPaddingValue("NoPadding");
      }
    });

    paddingBox.valueProperty().addListener((obs, oldValue, newValue) -> {
      if (newValue == null) {
        disableSaveButton();
      } else {
        enableSaveButton();
      }
    });
  }

  private void initializeActions() {
    saveButton.setOnAction(e -> {
      saveParams();
      window.close();
    });
  }

  private void openWindow() {
    createGrid();
    root.getChildren().add(grid);
    window.setScene(scene);
    window.showAndWait();
  }

  /**
   * Opens the OptionsWindow.
   */
  public String display() {

    setLabels();
    clearForm();
    initializeListeners();
    initializeActions();
    openWindow();

    return toString();
  }

  /**
   * Returns all saveOptions as String connected with "/".
   *
   * @return
   */
  public String toString() {
    return save + "/"
            + encryptionType + "/"
            + blockmode + "/"
            + padding + "/"
            + keySize + "/"
            + hashOrMac + "/"
            + password;
  }
}
