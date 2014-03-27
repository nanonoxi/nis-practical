package fileSecurity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.Security;

/**
 * Created by Daniel on 3/27/14.
 */
public class Cryptics {

    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    private Cipher aes;
    private Cipher rsa;
    private MessageDigest digest;
    private SecretKeySpec aesKEY;
    private String hash="SHA";
    byte[] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    IvParameterSpec ivSpec;

//Construct
    public Cryptics()
    {
        prepRSA();
    }

    public Cryptics(String aesPassPhrase)
    {
        try
        {
            //AES Key
            aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            digest = MessageDigest.getInstance(hash);
            digest.update(aesPassPhrase.getBytes());
            aesKEY = new SecretKeySpec(digest.digest(),0,16,"AES");
            ivSpec = new IvParameterSpec(iv);

            //RSA Prep

        }catch(Exception e){e.printStackTrace();}
    }

//AES
    public byte[] EncryptAES(String message)
    {
        byte[] cipherText;
        try
        {
            aes.init(Cipher.ENCRYPT_MODE, aesKEY,ivSpec);
            cipherText = aes.doFinal(message.getBytes());
        }catch (Exception e ){e.printStackTrace();return null;}
        return cipherText.clone();
    }

    public String DecryptAES(byte[] cipherText)
    {
        String message = "";

        try
        {
            aes.init(Cipher.DECRYPT_MODE, aesKEY,ivSpec);
            message = new String(aes.doFinal(cipherText));
        }
        catch (Exception e){e.printStackTrace();}
        return message;
    }

//RSA
    public Byte[] EncryptRSA(String message)
    {
        Byte[] cipherText = new Byte[50];
        return cipherText;
    }

    public String DecryptRSA(Byte[] cipherText)
    {
        String message = "";
        return message;
    }

    private void prepRSA()
    {
        try
        {
            rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        }catch(Exception e){e.printStackTrace();}
    }

}
