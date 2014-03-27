package fileSecurity.keyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.awt.SunHints;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

/**
 * Created by Daniel on 3/26/14.
 */
public class KeyGeneratorz {

    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String args[])
    {
        try
        {
            KeyPairGenerator key_gen = KeyPairGenerator.getInstance("RSA","BC");
            key_gen.initialize(1024);
            KeyPair keys = key_gen.generateKeyPair();

            Scanner input = new Scanner(System.in);
            System.out.println("client or server?");

            String host = input.nextLine();

            SaveKeyPair(keys, host);

            System.out.println("Saving keys for: "+host);

        }catch (Exception e){System.out.println();}
    }

    public static void SaveKeyPair(KeyPair keyPair, String pre) throws IOException
    {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        X509EncodedKeySpec x509 = new X509EncodedKeySpec(publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(pre+"-public.key");
        fos.write(x509.getEncoded());
        fos.close();

        PKCS8EncodedKeySpec pkcs = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        fos = new FileOutputStream(pre+"-private.key");
        fos.write(pkcs.getEncoded());
        fos.close();
    }


    public static Key LoadKey(String type, String pre ) throws Exception
    {
        //Read key
        File fileKey = new File(pre+"-"+type+".key");
        FileInputStream fis = new FileInputStream(pre+"-"+type+".key");
        byte[] encodedKey = new byte[(int) fileKey.length()];
        fis.read(encodedKey);
        fis.close();

        //Generate Key
        KeyFactory keyFact = KeyFactory.getInstance("RSA");

        if (type.equals("public"))
        {
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec((encodedKey));
            PublicKey key = keyFact.generatePublic(pubKeySpec);

            return key;
        }
        else if (type.equals("private"))
        {
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
            PrivateKey key = keyFact.generatePrivate(privateKeySpec);

            return key;
        }
        else
        {
            System.out.println("Invalid option selected");
            return null;
        }

    }
}
