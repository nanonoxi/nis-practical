package fileSecurity.keyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

/**
 * Created by Daniel on 3/26/14.
 */
public class KeyGenerator {

    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String args[])
    {
        try
        {
            KeyPairGenerator key_gen = KeyPairGenerator.getInstance("RSA","BC");
            KeyPair keys = key_gen.generateKeyPair();
            System.out.println(keys.getPublic());
        }catch (Exception e){System.out.println();}

    }
}
