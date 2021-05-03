package editor;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class IoResultTest {
  @Test
  void testIOResult(){
    String expectedData = "test";
    IoResult<String> result = new IoResult<>(true, expectedData);

    assertEquals(true, result.isOk());
    assertEquals(true, result.hasData());
    assertEquals(expectedData, result.getData());

    IoResult<String> result2 = new IoResult<>(true, null);
    assertEquals(false, result2.hasData());
  }
}
