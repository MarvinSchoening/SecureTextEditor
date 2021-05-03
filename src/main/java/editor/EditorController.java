package editor;

import java.io.File;

import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.TextArea;
import javafx.stage.FileChooser;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;


/**
 * Controller for the Editor.
 *
 * @author Marvin Schöning
 */
public class EditorController {

  @FXML
  private TextArea areaText;

  private TextFile currentTextFile;

  private EditorModel model;

  public EditorController(EditorModel model) {
    this.model = model;
  }

  @FXML
  private void onSaveAs() throws Exception {
    FileChooser fileChooser = new FileChooser();
    fileChooser.setInitialDirectory(new File("./"));
    fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("STE Files", "*.ste"));
    fileChooser.setInitialFileName("*.ste");

    File file = fileChooser.showSaveDialog(null);
    if (file != null) {
      //Save Files as .ste Files
      if (file.getName().endsWith(".ste")) {
        File steFile = new File(file.getName());
        TextFile textFile = new TextFile(
                steFile.toPath(),
                areaText.getText());
        model.save(textFile);
        currentTextFile = textFile;
      } else {
        throw new Exception(file.getName() + "hat keine valide Dateiendung!");
      }
    }
  }

  @FXML
  private void onSave() {
    if (currentTextFile != null) {
      TextFile textFile = new TextFile(
              currentTextFile.getFile(),
              areaText.getText()
      );

      model.save(textFile);
    } else {
      try {
        onSaveAs();
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  @FXML
  private void onLoad() {
    FileChooser fileChooser = new FileChooser();
    fileChooser.setInitialDirectory(new File("./"));
    // Only Load .ste Files
    fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("STE Files", "*.ste"));
    File file = fileChooser.showOpenDialog(null);
    if (file != null) {
      try {
        IoResult<TextFile> io = model.load(file.toPath());
        if (io.isOk() && io.hasData()) {
          currentTextFile = io.getData();
          areaText.clear();
          areaText.appendText(currentTextFile.getContent());

        } else {
          Alert alert = new Alert(Alert.AlertType.ERROR);
          alert.setHeaderText(null);
          alert.setTitle("Error beim Laden");
          alert.setContentText("Error beim Laden der Datei.");
          alert.show();
        }
      } catch (AEADBadTagException e) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setHeaderText(null);
        alert.setTitle("Error beim Laden");
        alert.setContentText("Error beim Laden der Datei. \nFehler: Passwort falsch");
        alert.show();
      } catch (BadPaddingException e) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setHeaderText(null);
        alert.setTitle("Error beim Laden");
        alert.setContentText("Error beim Laden der Datei. \nFehler: Passwort falsch");
        alert.show();
      } catch (Exception e) {
        e.printStackTrace();
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setHeaderText(null);
        alert.setTitle("Error beim Laden");
        alert.setContentText("Error beim Laden der Datei. \nFehler: " + e.getMessage());
        alert.show();
      }
    }
  }

  @FXML
  private void onClose() {
    model.close();
  }

  @FXML
  private void onAbout() {
    Alert alert = new Alert(Alert.AlertType.INFORMATION);
    alert.setHeaderText(null);
    alert.setTitle("About");
    alert.setContentText("Secure Text Editor zum Speichern und Laden von verschlüsselten und/oder "
            + "Passwort geschützten Dateien, welche durch einen "
            + "Hash auf Manipulation getestet werden.");
    alert.show();
  }

}
