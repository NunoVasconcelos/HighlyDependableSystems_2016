package file_system.fs_library;

import file_system.exceptions.DifferentTimestampException;
import file_system.exceptions.IntegrityViolationException;
import file_system.exceptions.QuorumNotVerifiedException;
import file_system.shared.ContentHashBlock;
import file_system.shared.PublicKeyBlock;
import file_system.utils.SHA1;
import file_system.utils.VerifyIntegrity;
import pteidlib.PteidException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.rmi.Naming;
import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.util.*;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
//import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
//import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
//import sun.security.pkcs11.wrapper.CK_MECHANISM;
//import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
//import sun.security.pkcs11.wrapper.PKCS11;
//import sun.security.pkcs11.wrapper.PKCS11Constants;

public class FS_Library {
	private static final int TAMANHO_BLOCO = 16000;
	private PrivateKey priv;
	private PublicKey pub;
	private String id;
    private ArrayList<RmiServerIntf> servers = new ArrayList<>();
    private static final int MAX_BYZANTINE_FAULTS = 1;
    private PublicKey pubKeyRead;
    private int RID = 0;
    private int timestamp = 0;
    private SecretKey sharedSecret;

    // TODO: make config file for servers...

    // public methods

	public void fs_init(ArrayList<String> ports) throws Exception, IntegrityViolationException, QuorumNotVerifiedException, DifferentTimestampException {
		// read config file
        // Path path = Paths.get("config.txt");
        // List<String> configLines = Files.readAllLines(path);
        // for(String line : configLines) serverPorts.add(line);

        // get remote objects (servers)
        RmiServerIntf server;
		for(String port : ports) {
			// create RMI connection with each block server
			server = (RmiServerIntf) Naming.lookup("//localhost/RmiServer" + port);
			servers.add(server);
		}

        System.setProperty("sun.rmi.transport.tcp.responseTimeout", "5000"); // TODO: not working

		// get client Public Key Certificate from the EID Card and register in the Key Server aka Block Server
		initPublicKey(); // now doing init of privKey as well

        // generate client id from publicKey
        this.id = SHA1.SHAsum(this.pub.getEncoded());

		// store publicKey on Key Server (Block Server)
        fileSystemRequest("storePubKey", new ArrayList<>(Collections.singletonList(this.pub)));
    }

    public void fs_write(int pos, byte[] content) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, IOException, IntegrityViolationException, QuorumNotVerifiedException, DifferentTimestampException {

        // get publicKeyBlock (which contains content hash block ids)
        String clientId = SHA1.SHAsum(this.pub.getEncoded());

        PublicKeyBlock publicKeyBlock = (PublicKeyBlock) fileSystemRequest("get", new ArrayList<>(Collections.singletonList(clientId)));

        if(!publicKeyBlock.getContentHashBlockIds().isEmpty())
            // check integrity
            VerifyIntegrity.verify(publicKeyBlock, publicKeyBlock.getSignature(), this.pub);

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
                ContentHashBlock currentBlock = (ContentHashBlock) fileSystemRequest("get", new ArrayList<>(Collections.singletonList(contentHashBlockIds.get(i))));

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
        for (String contentId : newHashBlockIds) concatenatedIds += contentId;
        byte[] signature = signData(concatenatedIds.getBytes());

        //new block updated
        publicKeyBlock.setContentHashBlockIds(newHashBlockIds, signature);

        //Increment the publicKeyBlock timestamp
        publicKeyBlock.incrementTS();


        // write updated publicKeyBlock (put_k)
        String hashPub = (String) fileSystemRequest("put_k", new ArrayList<>(Arrays.asList(publicKeyBlock, this.pub)));

        // verify
        if (id.equals(hashPub)) System.out.println("File stored successfully!");
        else throw new IntegrityViolationException();
	}

    public byte[] fs_read(PublicKey publicKey, int pos, int size) throws IOException, NoSuchAlgorithmException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, IntegrityViolationException, QuorumNotVerifiedException, DifferentTimestampException, InvalidKeyException {
		PublicKeyBlock publicKeyBlock;
		byte[] bytesRead = new byte[size];

		// check which public key will be used
		if(publicKey != null) pubKeyRead = publicKey;
        else pubKeyRead = this.pub;

		// get publicKeyBlock (which contains content hash block ids)
		String clientId = SHA1.SHAsum(pubKeyRead.getEncoded());
        publicKeyBlock = (PublicKeyBlock) fileSystemRequest("get", new ArrayList<>(Collections.singletonList(clientId)));

        // check integrity
        VerifyIntegrity.verify(publicKeyBlock, publicKeyBlock.getSignature(), pubKeyRead);

        // read blocks covered by pos+size
        List<String> contentHashBlockIds = publicKeyBlock.getContentHashBlockIds();
        byte[] result = "".getBytes(); //Byte stream with all the data from the blocks desired
        for (String id : contentHashBlockIds) {
            byte[] dstByteArray = new byte[result.length + TAMANHO_BLOCO];
            ContentHashBlock currentBlock = (ContentHashBlock) fileSystemRequest("get", new ArrayList<>(Collections.singletonList(id)));

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

	public List<PublicKey> fs_list() throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, IOException, NoSuchAlgorithmException, IntegrityViolationException, QuorumNotVerifiedException, DifferentTimestampException, InvalidKeyException {
		return (List<PublicKey>) fileSystemRequest("readPublicKeys", new ArrayList<>());
	}

    // private methods

    private static byte[] serialize(Object obj) throws IOException {
        try(ByteArrayOutputStream b = new ByteArrayOutputStream()){
            try(ObjectOutputStream o = new ObjectOutputStream(b)){
                o.writeObject(obj);
            }
            return b.toByteArray();
        }
    }

    private Object fileSystemRequest(String methodName, ArrayList<Object> args) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException, NoSuchAlgorithmException, IntegrityViolationException, DifferentTimestampException, InvalidKeyException, QuorumNotVerifiedException {

        if(methodName.equals("get") || methodName.equals("readPublicKeys")) {
            RID++;
            args.add(RID);
        }
        if(methodName.equals("put_k") || methodName.equals("put_h") || methodName.equals("storePubKey"))
        {
            timestamp++;
            args.add(timestamp);
        }

        // initializations
        Method method;

        //Add the method name to the argsArray so that the serverRequest function knows the function to be called
        ArrayList<Object> argsArray = new ArrayList<>();

        byte[] a = methodName.getBytes();
        byte[] b = serialize(args);
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);

        byte[] macDigest = generateMAC(c);
        argsArray.add(macDigest);
        argsArray.add(methodName);
        argsArray.add(args);
        Object[] arrayOfArgs = argsArray.toArray();


        //To get an array with (String, ArrayList<Object>) to call the requestServer function from the server
        Class[] classes = new Class[3];
        classes[0] = macDigest.getClass();
        classes[1] = "".getClass();
        classes[2] = args.getClass();

        Object response;
        HashMap<Integer, ArrayList<Object>> responses = new HashMap<>();
        int quorum = (2 * MAX_BYZANTINE_FAULTS) + 1;


        // execute request to all block servers
        for(RmiServerIntf server : servers) {
            method = server.getClass().getDeclaredMethod("serverRequest", classes);

            response = method.invoke(server, arrayOfArgs);

            // put response in corresponding bucket
            if(response != null) {
                ArrayList<Object> list;
                if(responses.containsKey(Arrays.hashCode(serialize(response)))) {
                    list = responses.get(Arrays.hashCode(serialize(response)));
                }
                else list = new ArrayList<>();
                list.add(response);
                responses.put(Arrays.hashCode(serialize(response)), list);
            }
        }

        // return response with higher timestamp, if quorum is verified
        for(Integer key : responses.keySet()) {
            if(responses.get(key).size() >= quorum) {

                ArrayList<Object> responseArray = (ArrayList<Object>) (responses.get(key).get(0));

                //Verify MAC
                byte[] receivedDigest = (byte[]) responseArray.get(0);    //Get the MAC from the arrayList
                responseArray.remove(0);    //Remove it so we can serialize the whole message without the MAC


                byte[] bytesFromMessage = serialize(responseArray); //Get the bytes from the whole message
                byte[] digest = generateMAC(bytesFromMessage);  //generate the MAC so we can compare

                if(!Arrays.equals(digest, receivedDigest)) {
                    System.out.println("Message integrity (MAC) not verified!");
                    throw new IntegrityViolationException();
                }

                //Verify the timestamp received from the servers, either from the put functions or the get function
                switch (methodName) {
                    case "put_h":
                    case "put_k":
                        //ArrayList<Object> returns pairs <id, wts> from the put_k or put_h. Since we have a bucket full of
                        //those with the same timestamp, we just need to grab one of them, and compare the timestamp
                        if (timestamp != (int) responseArray.get(1))
                            throw new DifferentTimestampException();
                        else    //if the timestamp is correct, return the String id, either from the put_k or put_h
                            return responseArray.get(0);
                    case "get":
                    case "readPublicKeys":
                        //ArrayList<Object> returns pairs <id, rid> from the get function. Since we have a bucket full of
                        //those with the same timestamp, we just need to grab one of them, and compare the timestamp
                        if (RID != (int) responseArray.get(1))
                            throw new DifferentTimestampException();
                        else    //if the timestamp is correct, return the publicKeyBlock
                            return responseArray.get(0);
                    case "storePubKey":
                        //Check if the server stored the correct Public Key, in case the server is byzantine
                        //Response object came in ArrayList with <String id, int wts>
                        String checkId = (String) responseArray.get(0);
                        int checkWts = (int) responseArray.get(1);

                        if (!this.id.equals(checkId))
                            throw new IntegrityViolationException();
                        if (timestamp != checkWts)
                            throw new DifferentTimestampException();
                        else
                            return checkId; //Not used in anything, but this function needs to return something. storePubKey was void.

                }
            }
        }
        throw new QuorumNotVerifiedException();
    }

    private void initPublicKey() throws CertificateException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException, PteidException, NoSuchProviderException {
		//this.pub = PTEIDLIB_Cert_Validation.main(); // to get publicKey from CC
		generateKeys();
	}

    private byte[] generateMAC(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {

        // create a MAC and initialize with the above key
        Mac mac = Mac.getInstance(this.sharedSecret.getAlgorithm());
        mac.init(this.sharedSecret);

        // create a digest from the byte array
        return mac.doFinal(data);
    }

	private void generateKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keyGen.initialize(1024, random);
		KeyPair pair = keyGen.generateKeyPair();
		this.priv = pair.getPrivate();
		this.pub = pair.getPublic();
        this.pubKeyRead = this.pub;

        //Generating a seed to create the secret key
        byte[] encoded = "group14SEC2016".getBytes();
        // generate MAC secret key
        this.sharedSecret = new SecretKeySpec(encoded, "HmacMD5");
	}

    private PublicKeyBlock getHigherTimestamp(ArrayList<PublicKeyBlock> publicKeyBlocks) { // TODO: not being used
        PublicKeyBlock higherTimestamp = null;
        for(PublicKeyBlock publicKeyBlock : publicKeyBlocks) {
            if(higherTimestamp == null) higherTimestamp = publicKeyBlock;
            else {
                int timeStamp = publicKeyBlock.getTimestamp();
                if(timeStamp > higherTimestamp.getTimestamp()) higherTimestamp = publicKeyBlock;
            }
        }
        return higherTimestamp;
    }

	private byte[] signData(byte[] buffer) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA1withRSA");
		dsa.initSign(this.priv);
		dsa.update(buffer);
		return dsa.sign();
        //return eIDLib_PKCS11_test.main(buffer); // to sign with CC
	}
}


