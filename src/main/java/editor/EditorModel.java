package editor;

import crypto.CryptoManager;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;

import java.util.Map;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;


/**
 * Editor Business Logic.
 *
 * @author Marvin Schöning
 */
public class EditorModel {

  // Save Options
  private static int SAVE = 0;
  private static int ENCRYPTION_TYPE = 1;
  private static int BLOCKMODE = 2;
  private static int PADDING = 3;
  private static int KEYSIZE = 4;
  private static int DIGEST_NAME = 5;
  private static int PASSWORD = 6;

  // Encrypted
  private static int KEY = 0;
  private static int CONTENT = 1;
  private static int IV = 2;
  private static int HASH_OR_MAC = 3;
  private static int MAC_KEY = 4;
  private static int SIGNATURE = 5;
  private static int SIGNATURE_KEY = 6;
  private static int SALT = 7;

  /**
   * Save encrypted editor input, choosen options and keys.
   *
   * @param textfile as TextFile
   */
  @SuppressWarnings("unchecked")
  public void save(TextFile textfile) {

    OptionsPage optionsPage = new OptionsPage(textfile.getContent());
    String saveOptionsConcat = optionsPage.display();

    String[] saveOptionsArray = saveOptionsConcat.split("/");

    if (saveOptionsArray[SAVE].equals("true")) {
      int keySize;
      if (saveOptionsArray[KEYSIZE].equals("null") || saveOptionsArray[KEYSIZE].equals("")) {
        keySize = 0;
      } else {
        keySize = Integer.parseInt(saveOptionsArray[KEYSIZE]);
      }

      String password = "";
      if (saveOptionsArray.length > PASSWORD) {
        password = saveOptionsArray[PASSWORD];
      }

      CryptoManager cm = new CryptoManager(
              textfile.getContent(),
              saveOptionsArray[ENCRYPTION_TYPE],
              saveOptionsArray[BLOCKMODE],
              saveOptionsArray[PADDING],
              saveOptionsArray[DIGEST_NAME],
              keySize,
              password);

      try {
        String[] encryptArray = cm.encrypt();
        JSONObject saveOptions = new JSONObject();
        saveOptions.put("text", encryptArray[CONTENT]);
        saveOptions.put("hashOrMac", encryptArray[HASH_OR_MAC]);
        saveOptions.put("signature", encryptArray[SIGNATURE]);
        saveOptions.put("signatureKey", encryptArray[SIGNATURE_KEY]);

        if (encryptArray[KEY] != null) {
          saveOptions.put("key", encryptArray[KEY]);
        }

        if (encryptArray[SALT] != null) {
          saveOptions.put("salt", encryptArray[SALT]);
        }

        if (encryptArray[IV] != null) {
          saveOptions.put("iv", encryptArray[IV]);
        }

        if (encryptArray[MAC_KEY] != null) {
          saveOptions.put("macKey", encryptArray[MAC_KEY]);
        }

        if (!saveOptionsArray[BLOCKMODE].equals("null")) {
          saveOptions.put("blockmode", saveOptionsArray[BLOCKMODE]);
        }

        saveOptions.put("encryptionType", saveOptionsArray[ENCRYPTION_TYPE]);
        saveOptions.put("padding", saveOptionsArray[PADDING]);
        saveOptions.put("digestName", saveOptionsArray[DIGEST_NAME]);


        Files.writeString(
                textfile.getFile(),
                saveOptions.toJSONString(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * Load encrypted file and return it decrypted.
   *
   * @param file as Path
   * @return decrypted textFile
   */
  public IoResult<TextFile> load(Path file) throws Exception {
    String text = Files.readString(file);
    TextFile textFile = new TextFile(file, text);

    JSONParser jsonParser = new JSONParser();
    Object obj = jsonParser.parse(textFile.getContent());
    JSONObject saveOptionsObject = (JSONObject) obj;

    HashMap<String, String> saveOptions = loadSaveOptions(saveOptionsObject);

    String[] keyArray = new String[4];
    keyArray[0] = saveOptions.get("key");
    keyArray[1] = saveOptions.get("iv");
    keyArray[2] = saveOptions.get("macKey");
    keyArray[3] = saveOptions.get("signatureKey");

    String password;
    if (saveOptions.containsKey("key")) {
      password = "";
    } else {
      PasswordPage pp = new PasswordPage();
      password = pp.display();
    }

    CryptoManager cm = new CryptoManager(
            saveOptions.get("text"),
            saveOptions.get("encryptionType"),
            saveOptions.get("blockmode"),
            saveOptions.get("padding"),
            saveOptions.get("digestName"),
            saveOptions.get("hashOrMac"),
            saveOptions.get("signature"),
            keyArray,
            password,
            saveOptions.get("salt"));

    String decrypted = cm.decrypt();

    TextFile newCurrentTextFile = new TextFile(file, decrypted);
    return new IoResult<>(true, newCurrentTextFile);
  }

  /**
   * Load SaveOptions from .ste File
   *
   * @param jsonObject saveOptions in json format
   * @return HashMap of choosen saveOptions
   */
  @SuppressWarnings("unchecked")
  private HashMap<String, String> loadSaveOptions(JSONObject jsonObject) {
    HashMap<String, String> saveOptions = new HashMap<>();
    for (Object e : jsonObject.entrySet()) {
      Map.Entry<String, String> entry = (Map.Entry) e;
      saveOptions.put(entry.getKey(), entry.getValue());
    }

    return saveOptions;
  }

  /**
   * Exits the programm.
   */
  @SuppressFBWarnings("DM_EXIT")
  public void close() {
    System.exit(0);
  }

}
