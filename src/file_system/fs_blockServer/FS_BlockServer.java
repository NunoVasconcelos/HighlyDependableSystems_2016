package file_system.fs_blockServer;

import file_system.*;

import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Hashtable;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.registry.*;
import java.util.List;

public class FS_BlockServer extends UnicastRemoteObject implements RmiServerIntf {
	
	private Hashtable<String, Block> blocks = new Hashtable<>();
	private List<PublicKey> publicKeys = new ArrayList<>();

	public FS_BlockServer() throws RemoteException {
		super(0);    // required to avoid the 'rmic' step, see below
	}

	public static void main(String args[]) throws RemoteException, MalformedURLException {
		System.out.println("RMI server started");

        try { //special exception handler for registry creation
            LocateRegistry.createRegistry(1099);
            System.out.println("java RMI registry created.");
        } catch (RemoteException e) {
            //do nothing, error means registry already exists
            System.out.println("java RMI registry already exists.");
        }

		//Instantiate RmiServer
		FS_BlockServer obj = new FS_BlockServer();

		// Bind this object instance to the name "RmiServer"
		Naming.rebind("//localhost/RmiServer", obj);
		System.out.println("PeerServer bound in registry");
	}

    public Block get(String id) {
		// if publicKeyBlock do not exist, create
		if (!blocks.containsKey(id)) {
			PublicKeyBlock publicKeyBlock = new PublicKeyBlock();
			this.blocks.put(id, publicKeyBlock);
			return publicKeyBlock;
		} else {
			// check integrity
			return this.blocks.get(id);
		}
	}

	public String put_k(PublicKeyBlock publicKeyBlock, byte[] signature, PublicKey public_key) throws NoSuchAlgorithmException {
		// check integrity
		List<String> contentHashBlockIds = publicKeyBlock.getContentHashBlockIds();
		String concatenatedIds = "";
		for(String contentId : contentHashBlockIds) {
			concatenatedIds += contentId;
		}
		DigitalSignature ds = new DigitalSignature();
		boolean integrityVerified = ds.verifySign(concatenatedIds.getBytes(), signature, public_key);
        String id = "Error: integrity not guaranteed";
		if (integrityVerified) {
			// store publicKeyBlock
            id = SHA1.SHAsum(public_key.getEncoded());
            blocks.put(id, publicKeyBlock);
		} else {
			System.out.println("put_k - Error: integrity not guaranteed");
		}
		return id;
	}

	// store contentHashBlock
	public String put_h(byte[] data) throws NoSuchAlgorithmException {
        String id = SHA1.SHAsum(data);
		ContentHashBlock contentHashBlock = new ContentHashBlock(data);
		blocks.put(id, contentHashBlock);
		return id;
	}

	public void storePubKey(PublicKey publicKey) {
		publicKeys.add(publicKey);
	}

	public List<PublicKey> readPublicKeys() {
		return publicKeys;
	}
}
