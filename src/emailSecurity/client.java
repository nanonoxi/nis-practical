package emailSecurity;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Properties;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import javax.mail.internet.MimeMultipart;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;

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

        System.out.println("Setting properties ...");
        Properties props = new Properties();
        //props.put("mail.debug", "true");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", Config.HOST);
        props.put("mail.smtp.port", Config.PORT);

        System.out.println("Creating a session ...");
        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(Config.USERNAME, Config.PASSWORD);
                    }
                });


        System.out.println("Creating email body ...");
        String emailContent = Config.CONTENT;
        String emailSubject = Config.SUBJECT;
        MimeMessage body = new MimeMessage(session);
        try {
            body.setFrom(new InternetAddress(Config.FROM_ADDRESS));
            InternetAddress[] addresses = {new InternetAddress((Config.TO_ADDRESS)), new InternetAddress("nisuctassignment+dan@gmail.com")};
            body.setRecipients(Message.RecipientType.TO, addresses);
            //body.setRecipient(Message.RecipientType.TO, new InternetAddress(Config.TO_ADDRESS));
            body.setSubject(emailSubject);
            body.setContent(emailContent, "text/plain");
            body.saveChanges();
        } catch (MessagingException e) {
            e.printStackTrace();
            System.exit(0);
        }

        System.out.println("Creating command map for Bouncy Castle provider ...");
        MailcapCommandMap commandMap = (MailcapCommandMap) CommandMap.getDefaultCommandMap();

        commandMap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
        commandMap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
        commandMap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
        commandMap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
        commandMap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

        CommandMap.setDefaultCommandMap(commandMap);

        System.out.println("Initializing keystore ...");
        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance(Config.KEY_TYPE);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        System.out.println("Loading keys ...");
        try {
            keystore.load(new FileInputStream(Config.KEY_LOCATION), Config.KEY_PASSWORD.toCharArray());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        System.out.println("Retrieving private key from p12 file ...");
        PrivateKey privateKey = null;
        try {
            privateKey = (PrivateKey)keystore.getKey(Config.KEY_ALIAS, Config.KEY_PASSWORD.toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        // load certificate
        System.out.println("Retrieving certificate ...");
        Certificate certificate = null;
        try {
            certificate = keystore.getCertificate(Config.KEY_ALIAS);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        /** create SMIMESignedGenerator */
        System.out.println("Create SMIME signed generator ...");
        SMIMECapabilityVector capabilities = new SMIMECapabilityVector();
        capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
        capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
        capabilities.addCapability(SMIMECapability.dES_CBC);
        capabilities.addCapability(SMIMECapability.aES256_CBC);

        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(new SMIMEEncryptionKeyPreferenceAttribute(
                new IssuerAndSerialNumber(
                        new X500Name(((X509Certificate) certificate).getIssuerDN().getName()),
                                ((X509Certificate) certificate).getSerialNumber())));
        attributes.add(new SMIMECapabilitiesAttribute(capabilities));


        SMIMESignedGenerator signer = new SMIMESignedGenerator();
        try {
            signer.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
                    .build("SHA1withRSA", privateKey, (X509Certificate) certificate));
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

        ArrayList<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(certificate);
        try {
            signer.addCertificates(new JcaCertStore(certificates));
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

        /** sign email */
        System.out.println("Signing email ...");
        MimeMultipart smime = null;
        try {
            smime = signer.generate(body);
        } catch (SMIMEException e) {
            e.printStackTrace();
        }

        /** encrypt email */
        MimeMessage signedMessage = new MimeMessage(session);

        // Set all original MIME headers in the signed message
        Enumeration headers = null;
        try {
            headers = body.getAllHeaderLines();
        } catch (MessagingException e) {
            e.printStackTrace();
        }
        while (headers.hasMoreElements()) {
            try {
                signedMessage.addHeaderLine((String) headers.nextElement());
            } catch (MessagingException e) {
                e.printStackTrace();
            }
        }

        // Set the content of the signed message
        try {
            signedMessage.setContent(smime);
            signedMessage.saveChanges();
        } catch (MessagingException e) {
            e.printStackTrace();
        }

        /** send email */
        System.out.println("Sending mail ...");
        try {
            Transport.send(signedMessage);
        } catch (MessagingException e) {
            e.printStackTrace();
        }

        System.out.println("Done.");
    }

    public static void main (String args []) {
        (new Client()).run();
    }
}