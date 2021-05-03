package editor;

import javafx.geometry.Insets;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.layout.GridPane;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class PasswordPage {
  private Stage window;
  private GridPane grid;
  private Scene scene;
  private Group root;

  private String password;

  PasswordPage() {
    scene = new Scene(new Group(), 450, 250);

    grid = new GridPane();

    window = new Stage();
    window.initModality(Modality.APPLICATION_MODAL);
    window.setTitle("Einstellungen");
    window.setMinHeight(250);

    root = (Group) scene.getRoot();
  }

  /**
   * Displays a Password Input Field and a confirm button.
   *
   * @return password that was entered
   */
  public String display() {
    Label label = new Label();
    label.setText("Passwort eingeben: ");

    PasswordField passwordField = new PasswordField();

    Button confirmButton = new Button("Bestätigen");

    confirmButton.setOnAction(e -> {
      password = passwordField.getText();
      window.close();
    });

    grid.setVgap(4);
    grid.setHgap(10);

    grid.setPadding(new Insets(5));
    grid.add(label, 1, 0);
    grid.add(passwordField, 1, 1);
    grid.add(confirmButton, 1, 2);

    root.getChildren().add(grid);
    window.setScene(scene);
    window.showAndWait();

    return password;
  }

}
