package emailSecurity;

import com.sun.mail.smtp.SMTPMessage;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Properties;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Daniel Burnham-King
 * @author Merada Richter
 * 2014/03/26
 */
public class Client {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private void run() {
        /*
        Provide the email "essentials": SMTP server host & port, email addresses (sender & receiver), a subject, content, and the sending user's password
        Add BC as a new crypto provider
        Retrieve the cert from your Java Keystore
        Create and sign the email using the BC API/libraries
        Send the email
         */

        /** initialize session */
        final String username = "nisuctassignment@gmail.com";
        final String password = "nis@uct2014";

        Properties props = new Properties();
        props.put("mail.debug", "true");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", Config.HOST);
        props.put("mail.smtp.port", Config.PORT);

        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password);
                    }
                });

        /** retrieve private key from p12 file */
        String keyAlias = "key from secure.comodo.com";
        String p12Password = "nis@uct2014";

        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        try {
            keystore.load(this.getClass().getClassLoader().getResourceAsStream("../../keys/niskey.p12"), p12Password.toCharArray());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        PrivateKey key = null;
        try {
            key = (PrivateKey)keystore.getKey(keyAlias, p12Password.toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        /** sign email */
        String emailContent = "Hello world";
        String emailSubject = "Subject";


        // signing email
        //Smsg = Sign(loginSession,msg) // Sign with certificate private key
        /** encrypt email */

        //Encrypt(loginSession, Smsg) // Encrypt with certificate pub key of toUser

        /** send email */
        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("nisuctassignment@gmail.com"));
            message.setRecipients(Message.RecipientType.TO,
                    InternetAddress.parse("nisuctassignment+dan@gmail.com"));
            message.setSubject(emailSubject);
            message.setText(emailContent);

            Transport.send(message);

            System.out.println("Done");

        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main (String args []) {
        (new Client()).run();
    }
}