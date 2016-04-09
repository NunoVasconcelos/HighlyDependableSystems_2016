package file_system.fs_library;

import pteidlib.PTEID_Certif;
import pteidlib.PteidException;
import pteidlib.pteid;
import sun.security.pkcs11.wrapper.PKCS11;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.*;
import java.security.cert.PKIXRevocationChecker.Option;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;


public final class PTEIDLIB_Cert_Validation {


    public static PublicKey main()  {
       
    	X509Certificate cert = null;
        
        try
        {
            
        System.out.println("            //Load the PTEidlibj");

        System.loadLibrary("pteidlibj");
        pteid.Init(""); // Initializes the eID Lib
        pteid.SetSODChecking(false); // Don't check the integrity of the ID, address and photo (!)

        
        
        PKCS11 pkcs11;      
        String osName = System.getProperty("os.name");
        String javaVersion = System.getProperty("java.version");
        System.out.println("Java version: " + javaVersion);
    
        java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();
     
            String libName = "libbeidpkcs11.so";
            
            // access the ID and Address data via the pteidlib
            System.out.println("            -- accessing the ID  data via the pteidlib interface");

            
            cert=getCertFromByteArray(getCertificateInBytes(0));
            System.out.println("Citized Authentication Certificate "+cert);
            System.out.println("===>Issuer: "+cert.getIssuerX500Principal().getName());
            
            FileOutputStream fos = new FileOutputStream("myCert.crt");
            fos.write( cert.getEncoded() );
            fos.flush();
            fos.close();

            /* load anchor. If you are using the "Certificação de Autenticação do Cartão de Cidadão",
             you can either:
             a) validate against the various (10 at the time of writing) certificates available at :
             
             https://pki.cartaodecidadao.pt/publico/certificado/cc_ec_cidadao_autenticacao/
     
            b) use the issuer information available in the certificate to be validate (see line above) to 
             determine which certificate to use as root anchor.
             
             In this example, we use just a specific one ("EC de Autenticação do Cartão de Cidadão 0008").
             
             */
            
            
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            
            FileInputStream in = new FileInputStream("EC_de_Autenticacao_do_Cartao_de_Cidadao_0008.cer");
            Certificate trust = cf.generateCertificate(in);
            
            /* Construct a CertPathBuilder */
            TrustAnchor anchor = new TrustAnchor((X509Certificate) trust, null);
            Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
            trustAnchors.add(anchor);
            
            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setCertificate(cert);

        
            PKIXBuilderParameters params=new PKIXBuilderParameters(trustAnchors, certSelector);
            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
            
            /* Enable usage of revocation lists */
            PKIXRevocationChecker rc = (PKIXRevocationChecker)cpb.getRevocationChecker();
            rc.setOptions(EnumSet.of(Option.PREFER_CRLS));
            params.addCertPathChecker(rc);
            

            CertPathBuilderResult cpbr = cpb.build(params);
            System.out.println("CertPathBuilderResult"+cpbr);
            
            System.out.println("****************************");
            
            /* Now Validate the Certificate Path */
            
            CertPath cp = cpbr.getCertPath();
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            CertPathValidatorResult cpvr = cpv.validate(cp, params);
            
            /* If no exception is generated here, it means that validation was successful */
            System.out.println("Validation successful");

            
            
            pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD); //OBRIGATORIO Termina a eID Lib
                      
        }  catch (Throwable e)
        {
            System.out.println("[Catch] Exception: " + e.getMessage());
            e.printStackTrace();
            
        }
        
        return cert.getPublicKey();
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
            int i = 0;
            
            certificate_bytes = certs[n].certif; //gets the byte[] with the n-th certif
            
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

