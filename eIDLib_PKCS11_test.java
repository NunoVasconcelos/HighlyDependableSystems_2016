import pteidlib.PTEID_ADDR;
import pteidlib.PTEID_Certif;
import pteidlib.PTEID_ID;
import pteidlib.PTEID_PIC;
import pteidlib.PTEID_Pin;
import pteidlib.PTEID_TokenInfo;
import pteidlib.PteidException;
import pteidlib.pteid;

import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.lang.reflect.Method;
import javax.crypto.*;

import java.io.IOException;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class eIDLib_PKCS11_test {


    public static void main(String args[])  {
        try {
        System.out.println("            //Load the PTEidlibj");
        System.loadLibrary("pteidlibj");
        pteid.Init(""); // Initializes the eID Lib
        pteid.SetSODChecking(false); // Don't check the integrity of the ID, address and photo (!)

        
        
        PKCS11 pkcs11;
        String osName = System.getProperty("os.name");
        String javaVersion = System.getProperty("java.version");
        System.out.println("Java version: " + javaVersion);
    
        java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();
     
            String libName = "libpteidpkcs11.so";
            
            // access the ID and Address data via the pteidlib
            System.out.println("            -- accessing the ID  data via the pteidlib interface");

            showInfo();
            
            X509Certificate cert=getCertFromByteArray(getCertificateInBytes(0));
            System.out.println("Citized Authentication Certificate "+cert);
            
            // access the ID and Address data via the pteidlib
            System.out.println("            -- generating signature via the PKCS11 interface");

            
            if (-1 != osName.indexOf("Windows"))
                libName = "pteidpkcs11.dll";
            else if (-1 != osName.indexOf("Mac"))
                libName = "pteidpkcs11.dylib";
            Class pkcs11Class = Class.forName("sun.security.pkcs11.wrapper.PKCS11");
            if (javaVersion.startsWith("1.5."))
            {
                Method getInstanceMethode = pkcs11Class.getDeclaredMethod("getInstance", new Class[] { String.class, CK_C_INITIALIZE_ARGS.class, boolean.class });
                pkcs11 = (PKCS11)getInstanceMethode.invoke(null, new Object[] { libName, null, false });
            }
            else
            {
                Method getInstanceMethode = pkcs11Class.getDeclaredMethod("getInstance", new Class[] { String.class, String.class, CK_C_INITIALIZE_ARGS.class, boolean.class });
                pkcs11 = (PKCS11)getInstanceMethode.invoke(null, new Object[] { libName, "C_GetFunctionList", null, false });
            }

            //Open the PKCS11 session
            System.out.println("            //Open the PKCS11 session");
            long p11_session = pkcs11.C_OpenSession(0, PKCS11Constants.CKF_SERIAL_SESSION, null, null);

	    // Token login 
            System.out.println("            //Token login");
            pkcs11.C_Login(p11_session, 1, null);
            CK_SESSION_INFO info = pkcs11.C_GetSessionInfo(p11_session);
	
	    // Get available keys
            System.out.println("            //Get available keys");
            CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[1];
            attributes[0] = new CK_ATTRIBUTE();
            attributes[0].type = PKCS11Constants.CKA_CLASS;
            attributes[0].pValue = new Long(PKCS11Constants.CKO_PRIVATE_KEY);

            pkcs11.C_FindObjectsInit(p11_session, attributes);
            long[] keyHandles = pkcs11.C_FindObjects(p11_session, 5);

	    // points to auth_key
            System.out.println("            //points to auth_key. No. of keys:"+keyHandles.length);

            long signatureKey = keyHandles[0];		//test with other keys to see what you get
            pkcs11.C_FindObjectsFinal(p11_session);
            
            
            // initialize the signature method
            System.out.println("            //initialize the signature method");
      	    CK_MECHANISM mechanism = new CK_MECHANISM();
            mechanism.mechanism = PKCS11Constants.CKM_SHA1_RSA_PKCS;
            mechanism.pParameter = null;
            pkcs11.C_SignInit(p11_session, mechanism, signatureKey);


		//...
            
            // sign
            System.out.println("            //sign");
            byte[] signature = pkcs11.C_Sign(p11_session, "data".getBytes(Charset.forName("UTF-8")));
            System.out.println("            //signature:"+encoder.encode(signature));

		//...
            
            
            pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD); //OBRIGATORIO Termina a eID Lib

        }  catch (Throwable e)
        {
            System.out.println("[Catch] Exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    
    
    
    public static void showInfo() {
        try {
            
            int cardtype = pteid.GetCardType();
            switch (cardtype)
            {
                case pteid.CARD_TYPE_IAS07:
                    System.out.println("IAS 0.7 card\n");
                    break;
                case pteid.CARD_TYPE_IAS101:
                    System.out.println("IAS 1.0.1 card\n");
                    break;
                case pteid.CARD_TYPE_ERR:
                    System.out.println("Unable to get the card type\n");
                    break;
                default:
                    System.out.println("Unknown card type\n");
            }
            
            // Read ID Data
            PTEID_ID idData = pteid.GetID();
            if (null != idData)
                PrintIDData(idData);
            
            
            // Read Picture Data
            PTEID_PIC picData = pteid.GetPic();
            if (null != picData){
                String photo = "photo.jp2";
                FileOutputStream oFile = new FileOutputStream(photo);
                oFile.write(picData.picture);
                oFile.close();
                System.out.println("Created " + photo);
            }
            
            // Read Pins
            PTEID_Pin[] pins = pteid.GetPINs();
            
            // Read TokenInfo
            PTEID_TokenInfo token = pteid.GetTokenInfo();
            
            // Read personal Data
            byte[] filein = {0x3F, 0x00, 0x5F, 0x00, (byte)0xEF, 0x07};
            byte[] file = pteid.ReadFile(filein, (byte)0x81);
            
            
            
        }
        catch (PteidException e){
            e.printStackTrace();
        }
        catch (IOException e){
            e.printStackTrace();
        }
    }
    
    private static void PrintIDData(PTEID_ID idData) {
        System.out.println("DeliveryEntity : " + idData.deliveryEntity);
        System.out.println("PAN : " + idData.cardNumberPAN);
        System.out.println("...");
    }
    

    //Returns the CITIZEN AUTHENTICATION CERTIFICATE
    public static byte[] getCitizenAuthCertInBytes(){
        return getCertificateInBytes(0); //certificado 0 no Cartao do Cidadao eh o de autenticacao
    }
    
    // Returns the n-th certificate, starting from 0
    private static  byte[] getCertificateInBytes(int n) {
        byte[] certificate_bytes = null;
        try {
            PTEID_Certif[] certs = pteid.GetCertificates();
            System.out.println("Number of certs found: " + certs.length);
            int i = 0;
	    for (PTEID_Certif cert : certs) {
                System.out.println("-------------------------------\nCertificate #"+(i++));
                System.out.println(cert.certifLabel);
            }
            
            certificate_bytes = certs[n].certif; //gets the byte[] with the n-th certif
            
            //pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD); // OBRIGATORIO Termina a eID Lib
        } catch (PteidException e) {
            e.printStackTrace();
        }
        return certificate_bytes;
    }
    
    public static X509Certificate getCertFromByteArray(byte[] certificateEncoded) throws CertificateException{
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certificateEncoded);
        X509Certificate cert = (X509Certificate)f.generateCertificate(in);
        return cert;
    }

}
