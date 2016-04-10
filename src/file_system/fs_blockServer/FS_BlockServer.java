package file_system.fs_blockServer;

import file_system.*;
import sun.security.rsa.RSAPublicKeyImpl;

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

public class FS_BlockServer extends UnicastRemoteObject implements RmiServerIntf {
	
	private Hashtable<String, Block> blocks = new Hashtable<>();
	private List<PublicKey> publicKeys = new ArrayList<>();

	public FS_BlockServer() throws RemoteException {
		super(0);    // required to avoid the 'rmic' step, see below
	}

	public static void main(String args[]) throws RemoteException, MalformedURLException {
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

    public Block get(String id) {
        System.out.println("[Method Call] get("+ id +")");
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

	public String put_k(PublicKeyBlock publicKeyBlock, byte[] signature, RSAPublicKeyImpl public_key) throws NoSuchAlgorithmException {
        System.out.println("[Method Call] put_k("+ publicKeyBlock + ", " + signature + ", " + public_key + ")");
		// check integrity
		List<String> contentHashBlockIds = publicKeyBlock.getContentHashBlockIds();
		String concatenatedIds = "";
		for(String contentId : contentHashBlockIds) {
			concatenatedIds += contentId;
		}
        concatenatedIds += publicKeyBlock.getTimestamp();
		boolean integrityVerified = DigitalSignature.verifySign(concatenatedIds.getBytes(), signature, public_key);
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

	// store ContentHashBlock
	public String put_h(byte[] data) throws NoSuchAlgorithmException {
        ContentHashBlock contentHashBlock = new ContentHashBlock(data);
		String id = SHA1.SHAsum(data);
		blocks.put(id, contentHashBlock);
		return id;
	}

    // store Public Key
	public void storePubKey(RSAPublicKeyImpl publicKey) {
		publicKeys.add(publicKey);
	}

    // get all Public Keys
	public List<PublicKey> readPublicKeys() {
        return publicKeys;
	}
}
