package fileSecurity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
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
        try
        {
            aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ivSpec = new IvParameterSpec(iv);
            prepRSA();
        }catch(Exception e){e.printStackTrace();}

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
            prepRSA();

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
        return cipherText;
    }

    public byte[] EncryptAES(String message, SecretKey key)
    {
        byte[] cipherText;
        try
        {
            aes.init(Cipher.ENCRYPT_MODE, key,ivSpec);
            cipherText = aes.doFinal(message.getBytes());
        }catch (Exception e ){e.printStackTrace();return null;}
        return cipherText;
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

    public String DecryptAES(byte[] cipherText, SecretKey key)
    {
        String message = "";

        try
        {
            aes.init(Cipher.DECRYPT_MODE, key,ivSpec);
            message = new String(aes.doFinal(cipherText));
        }
        catch (Exception e){e.printStackTrace();}
        return message;
    }

//RSA
    public byte[] EncryptRSAPrivate(String message, PrivateKey privKey)
    {
        byte[] cipherText;
        try
        {
            rsa.init(Cipher.ENCRYPT_MODE, privKey);
            cipherText = rsa.doFinal(message.getBytes());
        }catch (Exception e ){e.printStackTrace();return null;}
        return cipherText;
    }

    public byte[] EncryptRSAPublic(String message, PublicKey pubKey)
    {
        byte[] cipherText;
        try
        {
            rsa.init(Cipher.ENCRYPT_MODE, pubKey);
            cipherText = rsa.doFinal(message.getBytes());
        }catch (Exception e ){e.printStackTrace();return null;}
        return cipherText;
    }

    public String DecryptRSAPrivate(byte[] cipherText, PrivateKey privKey)
    {
        String message = "";
        try
        {
            rsa.init(Cipher.DECRYPT_MODE, privKey);
            message = new String(rsa.doFinal(cipherText));
        }
        catch (Exception e){e.printStackTrace();}
        return message;
    }

    public String DecryptRSAPublic(byte[] cipherText, PublicKey pubKey)
    {
        String message = "";
        try
        {
            rsa.init(Cipher.DECRYPT_MODE, pubKey);
            message = new String(rsa.doFinal(cipherText));
        }
        catch (Exception e){e.printStackTrace();}
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
