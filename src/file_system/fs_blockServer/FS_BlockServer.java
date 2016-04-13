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
		// if publicKeyBlock do not exist, create
		if (!blocks.containsKey(id)) {
			PublicKeyBlock publicKeyBlock = new PublicKeyBlock();
			this.blocks.put(id, publicKeyBlock);
			return publicKeyBlock;
		} else {
			return this.blocks.get(id);
		}
	}

    public String put_k(PublicKeyBlock publicKeyBlock, byte[] signature, RSAPublicKeyImpl public_key) throws NoSuchAlgorithmException, IntegrityViolationException {

        // check integrity
		VerifyIntegrity.verify(publicKeyBlock, signature, public_key);

        // store publicKeyBlock
		String id = SHA1.SHAsum(public_key.getEncoded());
        blocks.put(id, publicKeyBlock);
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
