package cordova.plugin.HttpAes256Key16;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

//自定义引入
import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class echoes a string called from JavaScript.
 */
public class HttpAes256Key16 extends CordovaPlugin {

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("coolMethod")) {
            String message = args.getString(0);
            this.coolMethod(message, callbackContext);
            return true;
        }else if(action.equals("Encrypt")){
            String key = args.getString(0);
            String iv = args.getString(1);
            String data = args.getString(2);
            this.Encrypt(data, key, iv, callbackContext);
        }else if(action.equals("Decrypt")){
            String key = args.getString(0);
            String iv = args.getString(1);
            String data = args.getString(2);
            this.Decrypt(data, key, iv, callbackContext);
        }
        return false;
    }

    //插件测试
    private void coolMethod(String message, CallbackContext callbackContext) {
        if (message != null && message.length() > 0) {
            callbackContext.success(message);
        } else {
            callbackContext.error("Expected one non-empty string argument.");
        }
    }

    //加密
    private void Encrypt(String encData ,String secretKey,String vector, CallbackContext callbackContext) {
      if(secretKey == null) {
        //return "";
        callbackContext.error("The Key is undefined.");
      }
      if(secretKey.length() != 16) {
        //return "";
        callbackContext.error("The length of the key must be 16.");
      }
      try{

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] raw = secretKey.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        IvParameterSpec iv = new IvParameterSpec(vector.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(encData.getBytes("utf-8"));
        //return Base64.encodeToString(encrypted, Base64.DEFAULT);
        String message = Base64.encodeToString(encrypted, Base64.DEFAULT);
        callbackContext.success(message);
      }
      catch (Exception ex){
        //return "";
        callbackContext.error("Runtime error.");
      }
    }

    //解密
    private void Decrypt(String sSrc,String key,String ivs, CallbackContext callbackContext) {
      try {
        byte[] raw = key.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(ivs.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        byte[] encrypted1 = Base64.decode(sSrc, Base64.DEFAULT);
        byte[] original = cipher.doFinal(encrypted1);
        String originalString = new String(original, "utf-8");
        //return originalString;
        callbackContext.success(originalString);
      } catch (Exception ex) {
        //return "";
        callbackContext.error("Runtime error.");
      }
    }

}
