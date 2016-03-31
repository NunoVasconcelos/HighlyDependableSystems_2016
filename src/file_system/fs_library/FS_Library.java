package file_system.fs_library;

import file_system.ContentHashBlock;
import file_system.DigitalSignature;
import file_system.PublicKeyBlock;
import file_system.SHA1;
import file_system.fs_blockServer.RmiServerIntf;
import pteidlib.PTEID_Certif;
import pteidlib.PteidException;
import pteidlib.pteid;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class FS_Library
{
	public static final int TAMANHO_BLOCO = 16000;
	private RmiServerIntf blockServer;
    private PrivateKey priv;
    private PublicKey pub;
    private String id ;

	public void fs_init() throws Exception {
		// create RMI connection with block server
		this.blockServer = (RmiServerIntf) Naming.lookup("//localhost/RmiServer");

		System.loadLibrary("pteidlibj");
        pteid.Init(""); // Initializes the eID Lib
        pteid.SetSODChecking(false); // Don't check the integrity of the ID, address and photo (!)
        //PKCS11 pkcs11;
        String osName = System.getProperty("os.name");
        String javaVersion = System.getProperty("java.version");
        System.out.println("Java version: " + javaVersion);
        java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();
        String libName = "libpteidpkcs11.so";

		// get client Public Key Certificate from the EID Card and register in the Key Server aka Block Server
        initPublicKey();

        // store publicKey on Key Server (Block Server)
		this.blockServer.storePubKey(this.pub);
		
		// generate client id from publicKey
		this.id = SHA1.SHAsum(this.pub.getEncoded());
	}


	public void fs_write(int pos, byte[] content) {
		PublicKeyBlock publicKeyBlock;
		try {
			// get publicKeyBlock (which contains content hash block ids)
			publicKeyBlock = (PublicKeyBlock)this.blockServer.get(this.id);
			List<String> contentHashBlockIds = publicKeyBlock.getContentHashBlockIds();
			List<String> newHashBlockIds = new ArrayList<String>();

			// if is not the file initialization, then check integrity
            String concatenatedIds = "";
			if(!contentHashBlockIds.isEmpty()) {
				// verify publicKeyBlock integrity
				for(String id : contentHashBlockIds) {
					concatenatedIds += id;
				}
				DigitalSignature ds = new DigitalSignature();
				boolean integrityVerified = ds.verifySign(concatenatedIds.getBytes(), publicKeyBlock.getSignature(), this.pub);
				if (!integrityVerified) {
					System.out.println("fs_write - Error: integrity not guaranteed");
					return;
				}
			}


            // get blocks that are covered by pos+size
			int firstBlock = pos / TAMANHO_BLOCO;
			int lastBlock = (pos + content.length) / TAMANHO_BLOCO;
			byte[] result = "".getBytes(); //Byte stream with all the data from the blocks desired

			if(!contentHashBlockIds.isEmpty()) {
				for(int i = firstBlock; i <= lastBlock; i++) {
					byte[] dstByteArray = new byte[result.length + TAMANHO_BLOCO];
					ContentHashBlock currentBlock = (ContentHashBlock) this.blockServer.get(contentHashBlockIds.get(i));
                    if(!(SHA1.SHAsum(currentBlock.getData()) == contentHashBlockIds.get(i))) {System.out.println("fs_write - Error: integrity not guaranteed"); return;}
					System.arraycopy(result, 0, dstByteArray, 0, result.length);
					System.arraycopy(currentBlock.getData(), 0, dstByteArray, result.length, TAMANHO_BLOCO);
					result = dstByteArray;

					//Change the bytes from the blocks retrieved to the content provided by the user
					System.arraycopy(content, 0, result, result.length%TAMANHO_BLOCO, content.length);
				}
			}
			else {
				result = content;
			}

            // update/create content blocks and write it on Block Server (put_h)
			int actualSize = result.length;
			for(int i = 0; i < result.length; i += TAMANHO_BLOCO) {
				byte[] dataToBlock = new byte[TAMANHO_BLOCO];
				if(actualSize < TAMANHO_BLOCO)	//If it is the last iteration (the last block) and it has a size<16000
					System.arraycopy(result, 0, dataToBlock, 0, actualSize);
				else
					System.arraycopy(result, i, dataToBlock, 0, TAMANHO_BLOCO);

				actualSize -= TAMANHO_BLOCO;

				String dataBlockHash = SHA1.SHAsum(dataToBlock);
				String id = this.blockServer.put_h(dataToBlock);

				if(id.equals("-1")) {
					System.out.println("Error: Hashing function not successful (put_h)");
					return;
				} else if(!(dataBlockHash.equals(id))) {		//Integrity check
					System.out.println("Error: integrity not guaranteed (put_h)");
					return;
				}else{
					newHashBlockIds.add(dataBlockHash);
				}
			}

			//Sign the concatenation of hashesIds
			concatenatedIds = "";
			for(String contentId : newHashBlockIds) {
				concatenatedIds += contentId;
			}
			byte[] signature = signData(concatenatedIds.getBytes());
			publicKeyBlock.setContentHashBlockIds(newHashBlockIds, signature);	//new block updated

			// write updated publicKeyBlock (put_k)
			String hashPub = this.blockServer.put_k(publicKeyBlock, signature, this.pub);

			// integrity check: check if returned id == this.id
			if (id.equals(hashPub))
				System.out.println("File stored successfully!");
			else
				System.out.println("Error: integrity not guaranteed");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

    public byte[] fs_read(PublicKey publicKey, int pos, int size) throws RemoteException, NoSuchAlgorithmException {
		PublicKeyBlock publicKeyBlock;
		byte[] bytesRead = new byte[size];
        PublicKey pubKey;

        // check which public key will be used
        if(publicKey == null) pubKey = this.pub;
        else pubKey = publicKey;

        // get publicKeyBlock (which contains content hash block ids)
        String clientId = SHA1.SHAsum(pubKey.getEncoded());
        publicKeyBlock = (PublicKeyBlock)this.blockServer.get(clientId);

        // verify publicKeyBlock integrity
        List<String> contentHashBlockIds = publicKeyBlock.getContentHashBlockIds();
        String concatenatedIds = "";
        for(String contentId : contentHashBlockIds) {
            concatenatedIds += contentId;
        }
        DigitalSignature ds = new DigitalSignature();
        boolean integrityVerified = ds.verifySign(concatenatedIds.getBytes(), publicKeyBlock.getSignature(), pubKey);

        if(integrityVerified) {
            // read blocks covered by pos+size
            int firstBlock = pos / TAMANHO_BLOCO;
            int lastBlock = (pos + size) / TAMANHO_BLOCO;
            byte[] result = "".getBytes(); //Byte stream with all the data from the blocks desired

            // take content from blocks to be returned
            for(int i = firstBlock; i <= lastBlock; i++) {
                byte[] dstByteArray = new byte[result.length + TAMANHO_BLOCO];
                ContentHashBlock currentBlock = (ContentHashBlock) this.blockServer.get(contentHashBlockIds.get(i));
                if(!(SHA1.SHAsum(currentBlock.getData()).equals(contentHashBlockIds.get(i))))
                    return "fs_read - Error: integrity not guaranteed".getBytes();
                System.arraycopy(result, 0, dstByteArray, 0, result.length);
                System.arraycopy(currentBlock.getData(), 0, dstByteArray, result.length, TAMANHO_BLOCO);
                result = dstByteArray;
            }

            //Put only the content desired in bytesRead
            System.arraycopy(result, pos%result.length, bytesRead, 0, size);
        } else {
            return "fs_read - Error: integrity not guaranteed".getBytes();
        }
		return bytesRead;
	}

	public List<PublicKey> fs_list() {
        List<PublicKey> publicKeys = new ArrayList<>();
        try {
            publicKeys = this.blockServer.readPublicKeys();
        } catch (Exception e) {
            e.printStackTrace();
        }
		return publicKeys;
	}

    // TODO: change this method to use CC
	private byte[] signData(byte[] buffer) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initSign(this.priv);
        dsa.update(buffer);
        byte[] realSig = dsa.sign();
		return realSig;
	}

    private void initPublicKey() throws CertificateException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException, PteidException {
        X509Certificate cert = getCertFromByteArray(getCertificateInBytes(0));
        PKIXCertPathValidatorResult result = validateCertificate(cert);
        // TODO: analyze result
        System.out.println("validateCertificate: " + result);
        this.pub = cert.getPublicKey();
    }

    private static  byte[] getCertificateInBytes(int n) throws PteidException {
        PTEID_Certif[] certs = pteid.GetCertificates();
        byte[] certificate_bytes = certs[n].certif;
        //pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD); // OBRIGATORIO Termina a eID Lib
        return certificate_bytes;
    }

	public static X509Certificate getCertFromByteArray(byte[] certificateEncoded) throws CertificateException {
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(certificateEncoded);
		X509Certificate cert = (X509Certificate)f.generateCertificate(in);
		return cert;
	}

    // TODO: code below not working
	private PKIXCertPathValidatorResult validateCertificate(X509Certificate cert) throws CertificateException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException {
	    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    List mylist = new ArrayList();
	    FileInputStream in = new FileInputStream("Cartao de Cidadao 002.cer");
	    System.out.println("in: " + in);
	    Certificate c = cf.generateCertificate(in);
	    mylist.add(c);
	    CertPath cp = cf.generateCertPath(mylist);
	    //Certificate trust = cf.generateCertificate(in);
	    TrustAnchor anchor = new TrustAnchor(cert, null);
	    PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
	    params.setRevocationEnabled(false);
	    CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
	    PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
	    System.out.println(result);
	    return result;
	  }
}
