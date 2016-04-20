package file_system.fs_blockServer;

import file_system.*;
import sun.security.rsa.RSAPublicKeyImpl;
import sun.security.util.ObjectIdentifier;


import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import static java.lang.Thread.sleep;

public class FS_BlockServer extends UnicastRemoteObject implements RmiServerIntf {
	
	private Hashtable<String, Block> blocks = new Hashtable<>();
	private List<PublicKey> publicKeys = new ArrayList<>();

	public FS_BlockServer() throws RemoteException {
		super(0);    // required to avoid the 'rmic' step, see below
	}

	public static void main(String args[]) throws RemoteException, MalformedURLException, InterruptedException {
		System.out.println("RMI server started");

        try { //special exception handler for registry creation
            LocateRegistry.createRegistry(Integer.parseInt(args[0]));
            System.out.println("java RMI registry created on port " + args[0]);
        } catch (RemoteException e) {
            //do nothing, error means registry already exists
            System.out.println("java RMI registry already exists on port " + args[0]);
        }

		//Instantiate RmiServer
		FS_BlockServer obj = new FS_BlockServer();

		// Bind this object instance to the name "RmiServer"
		Naming.rebind("//localhost/RmiServer" + args[0], obj);
		System.out.println("PeerServer bound in registry");
	}

	public Object serverRequest(String functionName, ArrayList<Object> args) throws InterruptedException, NoSuchAlgorithmException, DifferentTimestampException, IntegrityViolationException {

		Object obj = new Object();

		//TODO receiving the MACs and checking them

		if (functionName.equals("get"))		//get(String id, int RID)
			return get((String) args.get(0), (int) args.get(1));
		else if (functionName.equals("put_k"))	//put_k(PublicKeyBlock publicKey, Signature, int wts)
			return put_k((PublicKeyBlock) args.get(0), (RSAPublicKeyImpl) args.get(1),(int) args.get(2));
		else if (functionName.equals("put_h"))	//put_h(byte[] data, int wts)
			return put_h((byte[]) args.get(0), (int) args.get(1));
		else if (functionName.equals("storePubKey"))	//storePubKey(RSAPublickey publicKey, int wts)
			return storePubKey((RSAPublicKeyImpl) args.get(0), (int) args.get(1));
		else if (functionName.equals("readPublicKeys"))	//readPublicKeys(int RID)
			return readPublicKeys((int) args.get(0));

		return obj;
	}


    public ArrayList<Object> get(String id, int RID) throws InterruptedException {

		Block block;

		ArrayList<Object> response = new ArrayList<Object>();
		// if publicKeyBlock do not exist, create
		if (!blocks.containsKey(id)) {
			block = new PublicKeyBlock();
			blocks.put(id, block);
		} else {	//If it is any kind of block existent in the hashtable
			block = blocks.get(id);
		}

		response.add(block);
		response.add(RID);
		return response;
	}

    public ArrayList<Object> put_k(PublicKeyBlock publicKeyBlock, RSAPublicKeyImpl public_key, int wts) throws NoSuchAlgorithmException, IntegrityViolationException, DifferentTimestampException, InterruptedException {

		ArrayList<Object> response = new ArrayList<Object>();

		String id = SHA1.SHAsum(public_key.getEncoded());

		// check if timestamp is valid
		int timestamp = publicKeyBlock.getTimestamp();

        // check integrity
		VerifyIntegrity.verify(publicKeyBlock, publicKeyBlock.getSignature(), public_key);

        // store publicKeyBlock
		//RID is not relevant, we just get the old block to check the timestamps
		PublicKeyBlock oldPublicKeyBlock = (PublicKeyBlock) get(id,0).get(0);

		if(timestamp > oldPublicKeyBlock.getTimestamp())  blocks.put(id, publicKeyBlock);
		else throw new DifferentTimestampException();

		response.add(id);
		response.add(wts);

		return response;
	}

	// store ContentHashBlock
	public ArrayList<Object> put_h(byte[] data, int wts) throws NoSuchAlgorithmException {

		ArrayList<Object> response = new ArrayList<Object>();

		ContentHashBlock contentHashBlock = new ContentHashBlock(data);
		contentHashBlock.setTimestamp(wts);
		String id = SHA1.SHAsum(data);
		blocks.put(id, contentHashBlock);

		response.add(id);
		response.add(wts);
		return response;
	}

    // store Public Key
	public ArrayList<Object> storePubKey(RSAPublicKeyImpl publicKey, int wts) throws NoSuchAlgorithmException {
		ArrayList<Object> response = new ArrayList<>();
		String hash = SHA1.SHAsum(publicKey.getEncoded());

		publicKeys.add(publicKey);

		//Return must be <id, wts>, so that we check integrity and assure freshness with wts
		response.add(hash);
		response.add(wts);
		return response;
	}

    // get all Public Keys
	public ArrayList<Object> readPublicKeys(int RID) {
        ArrayList<Object> response = new ArrayList<>();

		response.add(publicKeys);
		response.add(RID);

		return response;
	}
}
