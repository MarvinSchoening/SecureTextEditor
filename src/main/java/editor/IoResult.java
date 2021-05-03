package editor;

/**
 * Helper Class for loading data to check if everything went fine.
 * @author Marvin Schöning
 */
public class IoResult<T> {

  private T data;
  private boolean ok;

  public IoResult(boolean ok, T data) {
    this.ok = ok;
    this.data = data;
  }

  public boolean isOk() {
    return ok;
  }

  public boolean hasData() {
    return data != null;
  }

  public T getData() {
    return data;
  }
}
