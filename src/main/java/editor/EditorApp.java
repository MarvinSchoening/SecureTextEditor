package editor;

import java.io.IOException;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;


/**
 * Editor Start Class.
 *
 * @author Marvin Schöning
 */

public class EditorApp extends Application {

    @Override
    public void start(Stage stage) {
        stage.setTitle("Secure Text Editor");

        FXMLLoader loader = new FXMLLoader(getClass().getResource("/Editor/ui.fxml"));
        loader.setControllerFactory(t -> new EditorController(new EditorModel()));

        try {
            stage.setScene(new Scene(loader.load()));
        } catch (IOException e) {
            System.out.println("FXML konnte nicht geladen werden");
            e.printStackTrace();
        }
        stage.show();
    }

    /**
     * Starts the Application.
     *
     * @param args args
     */
    public static void main(String[] args) {
        launch();
    }

}