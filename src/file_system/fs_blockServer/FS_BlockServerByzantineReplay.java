package file_system.fs_blockServer;


import file_system.*;
import sun.security.rsa.RSAPublicKeyImpl;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;

public class FS_BlockServerByzantineReplay extends UnicastRemoteObject implements RmiServerIntf{

    private Hashtable<String, Block> blocks = new Hashtable<>();
    private List<PublicKey> publicKeys = new ArrayList<>();
    private static String connString;
    private static Registry rmiRegistry;
    private static int port;
    private static SecretKey sharedSecret;
    private boolean firstBlock = true;
    private Block byzantineBlock;

    public FS_BlockServerByzantineReplay() throws RemoteException {
        super(0);    // required to avoid the 'rmic' step, see below
    }

    public static void main(String args[]) throws RemoteException, MalformedURLException, InterruptedException {
        System.out.println("RMI server started");

        try { //special exception handler for registry creation
            port = Integer.parseInt(args[0]);
            rmiRegistry = LocateRegistry.createRegistry(port);
            System.out.println("java RMI registry created on port " + args[0]);
        } catch (RemoteException e) {
            //do nothing, error means registry already exists
            System.out.println("java RMI registry already exists on port " + args[0]);
        }

        //Generate the secret key to create the MACs
        byte[] encoded = "group14SEC2016".getBytes();
        sharedSecret = new SecretKeySpec(encoded, "HmacMD5");

        //Instantiate RmiServer
        FS_BlockServerByzantineReplay obj = new FS_BlockServerByzantineReplay();

        // Bind this object instance to the name "RmiServer"
        connString = "//localhost/RmiServer" + args[0];
        Naming.rebind(connString, obj);
        System.out.println("PeerServer bound in registry");
    }

    public Object serverRequest(byte[] digest, String functionName, ArrayList<Object> args) throws InterruptedException, NoSuchAlgorithmException, DifferentTimestampException, IntegrityViolationException, IOException, InvalidKeyException {

        ArrayList<Object> response = new ArrayList<>();

        //Generating the MAC to check with the received MAC
        byte[] a = functionName.getBytes();
        byte[] b = serialize(args);
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);

        byte[] confirmedDigest = generateMAC(c);

        if(!Arrays.equals(digest, confirmedDigest)) {
            System.out.println("Message integrity not verified!");
            throw new IntegrityViolationException();
        }

        if (functionName.equals("get"))		//get(String id, int RID)
            response = get((String) args.get(0), (int) args.get(1));
        else if (functionName.equals("put_k"))	//put_k(PublicKeyBlock publicKey, Signature, int wts)
            response = put_k((PublicKeyBlock) args.get(0), (RSAPublicKeyImpl) args.get(1),(int) args.get(2));
        else if (functionName.equals("put_h"))	//put_h(byte[] data, int wts)
            response = put_h((byte[]) args.get(0), (int) args.get(1));
        else if (functionName.equals("storePubKey"))	//storePubKey(RSAPublickey publicKey, int wts)
            response = storePubKey((RSAPublicKeyImpl) args.get(0), (int) args.get(1));
        else if (functionName.equals("readPublicKeys"))	//readPublicKeys(int RID)
            response = readPublicKeys((int) args.get(0));


        byte[] messageBytes = serialize(response);
        byte[] MAC = generateMAC(messageBytes);
        response.add(0, MAC);

        return response;
    }

    private ArrayList<Object> get(String id, int RID) throws InterruptedException {

        Block block;


        ArrayList<Object> response = new ArrayList<>();
        // if publicKeyBlock do not exist, create
        if (!blocks.containsKey(id)) {
            block = new PublicKeyBlock();
            blocks.put(id, block);
        } else {	//If it is any kind of block existent in the hashtable
            block = blocks.get(id);

            ////////////////////////////////////////////////////////////
            ///////////////////// Byzantine Code   /////////////////////
            if(firstBlock)
            {
                byzantineBlock = block;
                firstBlock = false;
            }
            ///////////////////// Byzantine Code   /////////////////////
            ////////////////////////////////////////////////////////////
        }

        response.add(byzantineBlock);
        response.add(RID);
        return response;
    }

    private ArrayList<Object> put_k(PublicKeyBlock publicKeyBlock, RSAPublicKeyImpl public_key, int wts) throws NoSuchAlgorithmException, IntegrityViolationException, DifferentTimestampException, InterruptedException, IOException, InvalidKeyException {

        ArrayList<Object> response = new ArrayList<Object>();

        String id = SHA1.SHAsum(public_key.getEncoded());

        // check integrity
        VerifyIntegrity.verify(publicKeyBlock, publicKeyBlock.getSignature(), public_key);

        // store publicKeyBlock
        //RID is not relevant, we just get the old block to check the timestamps
        PublicKeyBlock oldPublicKeyBlock = (PublicKeyBlock) get(id,0).get(0);

        if(wts > oldPublicKeyBlock.getTimestamp())  blocks.put(id, publicKeyBlock);
        else throw new DifferentTimestampException();

        response.add(id);
        response.add(wts);

        return response;
    }

    // store ContentHashBlock
    private ArrayList<Object> put_h(byte[] data, int wts) throws NoSuchAlgorithmException {

        ArrayList<Object> response = new ArrayList<Object>();

        ContentHashBlock contentHashBlock = new ContentHashBlock(data);

        String id = SHA1.SHAsum(data);
        blocks.put(id, contentHashBlock);

        response.add(id);
        response.add(wts);
        return response;
    }

    // store Public Key
    private ArrayList<Object> storePubKey(RSAPublicKeyImpl publicKey, int wts) throws NoSuchAlgorithmException {
        ArrayList<Object> response = new ArrayList<>();
        String hash = SHA1.SHAsum(publicKey.getEncoded());

        publicKeys.add(publicKey);

        //Return must be <id, wts>, so that we check integrity and assure freshness with wts
        response.add(hash);
        response.add(wts);
        return response;
    }

    // get all Public Keys
    private ArrayList<Object> readPublicKeys(int RID) {
        ArrayList<Object> response = new ArrayList<>();

        response.add(publicKeys);
        response.add(RID);

        return response;
    }


    //Copied from FS_Library, to be used in the MAC generation
    private byte[] generateMAC(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {

        // create a MAC and initialize with the above key
        Mac mac = Mac.getInstance(this.sharedSecret.getAlgorithm());
        mac.init(this.sharedSecret);

        // create a digest from the byte array
        byte[] digest = mac.doFinal(data);
        return digest;
    }

    //Copied from FS_Library, to be used in the MAC generation
    private static byte[] serialize(Object obj) throws IOException {
        try(ByteArrayOutputStream b = new ByteArrayOutputStream()){
            try(ObjectOutputStream o = new ObjectOutputStream(b)){
                o.writeObject(obj);
            }
            return b.toByteArray();
        }
    }
}
