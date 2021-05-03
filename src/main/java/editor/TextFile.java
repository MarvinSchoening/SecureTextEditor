package editor;

import java.nio.file.Path;

/**
 * Saves content that was inserted and path that was choosen.
 * @author Marvin Schöning
 *
 */
public class TextFile {
  private final Path file;

  private final String content;

  public TextFile(Path file, String content) {
    this.file = file;
    this.content = content;
  }

  public Path getFile() {
    return file;
  }

  public String getContent() {
    return content;
  }
}
