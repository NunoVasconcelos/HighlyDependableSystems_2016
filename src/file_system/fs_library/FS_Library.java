package file_system.fs_library;

import file_system.*;
import file_system.fs_blockServer.RmiServerIntf;
import pteidlib.PteidException;

import java.io.FileNotFoundException;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

//import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
//import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
//import sun.security.pkcs11.wrapper.CK_MECHANISM;
//import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
//import sun.security.pkcs11.wrapper.PKCS11;
//import sun.security.pkcs11.wrapper.PKCS11Constants;

public class FS_Library {
	public static final int TAMANHO_BLOCO = 16000;
	private RmiServerIntf blockServer;
	private PrivateKey priv;
	private PublicKey pub;
	private String id;

	public void fs_init() throws Exception {
		// create RMI connection with block server
		this.blockServer = (RmiServerIntf) Naming.lookup("//localhost/RmiServer");

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
			publicKeyBlock = (PublicKeyBlock) this.blockServer.get(this.id);
			List<String> contentHashBlockIds = publicKeyBlock.getContentHashBlockIds();
			List<String> newHashBlockIds = new ArrayList<String>();

			// if is not the file initialization, then check integrity
			String concatenatedIds = "";
			if (!contentHashBlockIds.isEmpty()) {
				// verify publicKeyBlock integrity
				for (String id : contentHashBlockIds) {
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

			if (!contentHashBlockIds.isEmpty()) {
				for (int i = firstBlock; i <= lastBlock; i++) {
					byte[] dstByteArray = new byte[result.length + TAMANHO_BLOCO];
					ContentHashBlock currentBlock = (ContentHashBlock) this.blockServer.get(contentHashBlockIds.get(i));
					if (!(SHA1.SHAsum(currentBlock.getData()) == contentHashBlockIds.get(i))) {
						System.out.println("fs_write - Error: integrity not guaranteed");
						return;
					}
					System.arraycopy(result, 0, dstByteArray, 0, result.length);
					System.arraycopy(currentBlock.getData(), 0, dstByteArray, result.length, TAMANHO_BLOCO);
					result = dstByteArray;

					//Change the bytes from the blocks retrieved to the content provided by the user
					System.arraycopy(content, 0, result, result.length % TAMANHO_BLOCO, content.length);
				}
			} else {
				result = content;
			}

			// update/create content blocks and write it on Block Server (put_h)
			int actualSize = result.length;
			for (int i = 0; i < result.length; i += TAMANHO_BLOCO) {
				byte[] dataToBlock = new byte[TAMANHO_BLOCO];
				if (actualSize < TAMANHO_BLOCO)    //If it is the last iteration (the last block) and it has a size<16000
					System.arraycopy(result, 0, dataToBlock, 0, actualSize);
				else
					System.arraycopy(result, i, dataToBlock, 0, TAMANHO_BLOCO);

				actualSize -= TAMANHO_BLOCO;

				String dataBlockHash = SHA1.SHAsum(dataToBlock);
				String id = this.blockServer.put_h(dataToBlock);

				if (id.equals("-1")) {
					System.out.println("Error: Hashing function not successful (put_h)");
					return;
				} else if (!(dataBlockHash.equals(id))) {        //Integrity check
					System.out.println("Error: integrity not guaranteed (put_h)");
					return;
				} else {
					newHashBlockIds.add(dataBlockHash);
				}
			}

			//Sign the concatenation of hashesIds
			concatenatedIds = "";
			for (String contentId : newHashBlockIds) {
				concatenatedIds += contentId;
			}
			byte[] signature = signDataWithCC(concatenatedIds.getBytes());
			publicKeyBlock.setContentHashBlockIds(newHashBlockIds, signature);    //new block updated

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
		if (publicKey == null) pubKey = this.pub;
		else pubKey = publicKey;

		// get publicKeyBlock (which contains content hash block ids)
		String clientId = SHA1.SHAsum(pubKey.getEncoded());
		publicKeyBlock = (PublicKeyBlock) this.blockServer.get(clientId);

		// verify publicKeyBlock integrity
		List<String> contentHashBlockIds = publicKeyBlock.getContentHashBlockIds();
		String concatenatedIds = "";
		for (String contentId : contentHashBlockIds) {
			concatenatedIds += contentId;
		}
		DigitalSignature ds = new DigitalSignature();
		boolean integrityVerified = ds.verifySign(concatenatedIds.getBytes(), publicKeyBlock.getSignature(), pubKey);

		if (integrityVerified) {
			// read blocks covered by pos+size
			int firstBlock = pos / TAMANHO_BLOCO;
			int lastBlock = (pos + size) / TAMANHO_BLOCO;
			byte[] result = "".getBytes(); //Byte stream with all the data from the blocks desired

			// take content from blocks to be returned
			for (String id : contentHashBlockIds) {
				byte[] dstByteArray = new byte[result.length + TAMANHO_BLOCO];
				ContentHashBlock currentBlock = (ContentHashBlock) this.blockServer.get(id);
				if (!(SHA1.SHAsum(currentBlock.getData()).equals(id)))
					return "fs_read - Error: integrity not guaranteed".getBytes();
				System.arraycopy(result, 0, dstByteArray, 0, result.length);
				System.arraycopy(currentBlock.getData(), 0, dstByteArray, result.length, TAMANHO_BLOCO);
				result = dstByteArray;
			}

			//Put only the content desired in bytesRead
			System.arraycopy(result, pos % result.length, bytesRead, 0, size);
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

	private void initPublicKey() throws CertificateException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException, PteidException, NoSuchProviderException {
		//this.pub = PTEIDLIB_Cert_Validation.main();
		generateKeys();
	}

	private void generateKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keyGen.initialize(1024, random);
		KeyPair pair = keyGen.generateKeyPair();
		this.priv = pair.getPrivate();
		this.pub = pair.getPublic();
	}

	private byte[] signDataWithCC(byte[] buffer) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		//return eIDLib_PKCS11_test.main(buffer);
		return signData(buffer);
	}

	private byte[] signData(byte[] buffer) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature dsa = Signature.getInstance("SHA1withRSA");
		dsa.initSign(this.priv);
		dsa.update(buffer);
		byte[] realSig = dsa.sign();
		return realSig;
	}
}


