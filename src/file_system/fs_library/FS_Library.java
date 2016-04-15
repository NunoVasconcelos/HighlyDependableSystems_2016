package file_system.fs_library;

import file_system.*;
import file_system.fs_blockServer.RmiServerIntf;
import pteidlib.PteidException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.rmi.Naming;
import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

//import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
//import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
//import sun.security.pkcs11.wrapper.CK_MECHANISM;
//import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
//import sun.security.pkcs11.wrapper.PKCS11;
//import sun.security.pkcs11.wrapper.PKCS11Constants;

public class FS_Library {
	public static final int TAMANHO_BLOCO = 16000;
	private PrivateKey priv;
	private PublicKey pub;
	private String id;
	private ArrayList<String> serverPorts = new ArrayList<>(Arrays.asList("1099", "1098", "1097", "1096"));
	private ArrayList<RmiServerIntf> servers = new ArrayList<>();
    private static final int MAX_BYZANTINE_FAULTS = 1;
    private PublicKey pubKeyRead;

    // TODO: make config file for servers...

    // public methods

	public void fs_init() throws Exception, IntegrityViolationException, QuorumNotVerifiedException {
		RmiServerIntf server;

		for(String port : this.serverPorts) {
			// create RMI connection with block server
			server = (RmiServerIntf) Naming.lookup("//localhost/RmiServer" + port);
			servers.add(server);
		}

        System.setProperty("sun.rmi.transport.tcp.responseTimeout", "5000"); // TODO: not wotking...

		// get client Public Key Certificate from the EID Card and register in the Key Server aka Block Server
		initPublicKey(); // now doing init of privKey as well

		// store publicKey on Key Server (Block Server)
        fileSystemRequest("storePubKey", new ArrayList<>(Arrays.asList(this.pub)));

		// generate client id from publicKey
		this.id = SHA1.SHAsum(this.pub.getEncoded());
    }

    public void fs_write(int pos, byte[] content) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, IOException, IntegrityViolationException, QuorumNotVerifiedException {

        // get publicKeyBlock (which contains content hash block ids)
        String clientId = SHA1.SHAsum(this.pub.getEncoded());
        PublicKeyBlock publicKeyBlock = (PublicKeyBlock) fileSystemRequest("get", new ArrayList<>(Arrays.asList(clientId)));

        // if is not the file initialization, then check integrity
        List<String> contentHashBlockIds = publicKeyBlock.getContentHashBlockIds();
        String concatenatedIds;

        // get blocks that are covered by pos+size
        int firstBlock = pos / TAMANHO_BLOCO;
        int lastBlock = (pos + content.length) / TAMANHO_BLOCO;
        byte[] result = "".getBytes(); //Byte stream with all the data from the blocks desired

        if (!contentHashBlockIds.isEmpty()) {
            for (int i = firstBlock; i <= lastBlock; i++) {
                byte[] dstByteArray = new byte[result.length + TAMANHO_BLOCO];
                ContentHashBlock currentBlock = (ContentHashBlock) fileSystemRequest("get", new ArrayList<>(Arrays.asList(contentHashBlockIds.get(i))));

                // verify ContentHashBlock integrity
                if (!(SHA1.SHAsum(currentBlock.getData()).equals(contentHashBlockIds.get(i)))) {
                    throw new IntegrityViolationException();
                }

                System.arraycopy(result, 0, dstByteArray, 0, result.length);
                System.arraycopy(currentBlock.getData(), 0, dstByteArray, result.length, TAMANHO_BLOCO);
                result = dstByteArray;

                //Change the bytes from the blocks retrieved to the content provided by the user
                System.arraycopy(content, 0, result, result.length % TAMANHO_BLOCO, content.length);
            }
        } else result = content;


        // update/create content blocks and write it on Block Server (put_h)
        List<String> newHashBlockIds = new ArrayList<>();
        int actualSize = result.length;
        for (int i = 0; i < result.length; i += TAMANHO_BLOCO) {
            byte[] dataToBlock = new byte[TAMANHO_BLOCO];
            if (actualSize < TAMANHO_BLOCO)    //If it is the last iteration (the last block) and it has a size<16000
                System.arraycopy(result, 0, dataToBlock, 0, actualSize);
            else
                System.arraycopy(result, i, dataToBlock, 0, TAMANHO_BLOCO);

            actualSize -= TAMANHO_BLOCO;

            String id = (String) fileSystemRequest("put_h", new ArrayList<>(Arrays.asList(dataToBlock)));

            // verify ContentHashBlock integrity
            String dataBlockHash = SHA1.SHAsum(dataToBlock);
            if (!(dataBlockHash.equals(id))) throw new IntegrityViolationException();
            else newHashBlockIds.add(dataBlockHash);
        }

        //Sign the concatenation of hashesIds + timestamp
        concatenatedIds = "";
        LocalDateTime timestamp = LocalDateTime.now(); // TODO: use wts := wts + 1; (4.7) instead of current time???
        String timeStamp = timestamp.toString();
        for (String contentId : newHashBlockIds) concatenatedIds += contentId;
        concatenatedIds += timeStamp;
        byte[] signature = signData(concatenatedIds.getBytes());
        publicKeyBlock.setContentHashBlockIds(newHashBlockIds, signature, timestamp);    //new block updated

        // write updated publicKeyBlock (put_k)
        String hashPub = (String) fileSystemRequest("put_k", new ArrayList<>(Arrays.asList(publicKeyBlock, signature, this.pub)));

        // verify ContentHashBlock integrity
        if (id.equals(hashPub)) System.out.println("File stored successfully!");
        else throw new IntegrityViolationException();
	}

    public byte[] fs_read(PublicKey publicKey, int pos, int size) throws IOException, NoSuchAlgorithmException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, IntegrityViolationException, QuorumNotVerifiedException {
		PublicKeyBlock publicKeyBlock;
		byte[] bytesRead = new byte[size];

		// check which public key will be used
		if (publicKey == null) pubKeyRead = this.pub;
		else pubKeyRead = publicKey;

		// get publicKeyBlock (which contains content hash block ids)
		String clientId = SHA1.SHAsum(pubKeyRead.getEncoded());
        publicKeyBlock = (PublicKeyBlock) fileSystemRequest("get", new ArrayList<>(Arrays.asList(clientId)));

        // read blocks covered by pos+size
        List<String> contentHashBlockIds = publicKeyBlock.getContentHashBlockIds();
        byte[] result = "".getBytes(); //Byte stream with all the data from the blocks desired
        for (String id : contentHashBlockIds) {
            byte[] dstByteArray = new byte[result.length + TAMANHO_BLOCO];
            ContentHashBlock currentBlock = (ContentHashBlock) fileSystemRequest("get", new ArrayList<>(Arrays.asList(id)));

            // verify ContentHashBlock integrity
            if (!(SHA1.SHAsum(currentBlock.getData()).equals(id))) throw new IntegrityViolationException();

            System.arraycopy(result, 0, dstByteArray, 0, result.length);
            System.arraycopy(currentBlock.getData(), 0, dstByteArray, result.length, TAMANHO_BLOCO);
            result = dstByteArray;
        }

        //Put only the content desired in bytesRead
        System.arraycopy(result, pos % result.length, bytesRead, 0, size);
		return bytesRead;
	}

	public List<PublicKey> fs_list() throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, IOException, NoSuchAlgorithmException, IntegrityViolationException, QuorumNotVerifiedException {
		return (List<PublicKey>) fileSystemRequest("readPublicKeys", new ArrayList<>());
	}

    // private methods

    private Object fileSystemRequest(String methodName, ArrayList<Object> args) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException, NoSuchAlgorithmException, IntegrityViolationException, QuorumNotVerifiedException {
        // initializations
        Method method;
        Object[] argsArray = args.toArray();
        Class[] classes = new Class[args.size()];
        int i = 0;
        Object response;
        HashMap<Integer, ArrayList<Object>> responses = new HashMap<>();
        int quorum = (2 * MAX_BYZANTINE_FAULTS) + 1;
        for(Object arg : argsArray) {
            classes[i] = arg.getClass();
            i++;
        }
        ArrayList<PublicKeyBlock> publicKeyBlocksResponses = new ArrayList<>();

        // execute request to all block servers
        for(RmiServerIntf server : servers) {
            method = server.getClass().getDeclaredMethod(methodName, classes);
            try {
                response = method.invoke(server, argsArray);

                if(response instanceof PublicKeyBlock) { // TODO: timestamp just for PublicKeyBlock???
                    PublicKeyBlock publicKeyBlock = (PublicKeyBlock) response;

                    if(publicKeyBlock.getContentHashBlockIds().size() > 0) {
                        // verify PublicKeyBlock integrity
                        VerifyIntegrity.verify(publicKeyBlock, publicKeyBlock.getSignature(), this.pubKeyRead);
                    }

                    publicKeyBlocksResponses.add(publicKeyBlock);

                } else {
                    // put response in corresponding bucket
                    if (response != null) {
                        ArrayList<Object> list;
                        if (responses.containsKey(response.hashCode())) {
                            list = responses.get(response.hashCode());
                        } else list = new ArrayList<>();
                        list.add(response);
                        responses.put(response.hashCode(), list);
                    }
                }
            } catch (java.lang.reflect.InvocationTargetException e) {
                e.printStackTrace();
            }
        }

        if(responses.size() > 0) {
            // return response with higher timestamp, if quorum is verified
            for (Object key : responses.keySet()) {
                if (responses.get(key).size() > quorum) {
                    return responses.get(key).get(0); // the first one by default
                }
            }
        } else {
            return getHigherTimestamp(publicKeyBlocksResponses); // TODO: this is correct according to the algorithm???
        }
        throw new QuorumNotVerifiedException();
    }

    private Object getHigherTimestamp(ArrayList<PublicKeyBlock> publicKeyBlocks) {
        PublicKeyBlock higherTimestamp = null;
        for(PublicKeyBlock publicKeyBlock : publicKeyBlocks) {
            if(higherTimestamp == null) higherTimestamp = publicKeyBlock;
            else {
                LocalDateTime timeStamp = publicKeyBlock.getTimestamp();
                if(timeStamp.isAfter(higherTimestamp.getTimestamp())) higherTimestamp = publicKeyBlock;
            }
        }
        return higherTimestamp;
    }

    private void initPublicKey() throws CertificateException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException, PteidException, NoSuchProviderException {
		//this.pub = PTEIDLIB_Cert_Validation.main(); // to get publicKey from CC
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

	private byte[] signData(byte[] buffer) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA1withRSA");
		dsa.initSign(this.priv);
		dsa.update(buffer);
		return dsa.sign();
        //return eIDLib_PKCS11_test.main(buffer); // to sign with CC
	}
}


