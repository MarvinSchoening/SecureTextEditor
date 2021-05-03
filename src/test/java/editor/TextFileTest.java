package editor;

import java.io.File;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TextFileTest {
  @Test
  void testTextFile(){
    String expectedPath = ".\\test.ste";
    String expectedText = "test";
    File file = new File("./test.ste");
    TextFile textFile = new TextFile(file.toPath(), "test");

    assertEquals(expectedPath, String.valueOf(textFile.getFile()));
    assertEquals(expectedText, textFile.getContent());
  }
}
