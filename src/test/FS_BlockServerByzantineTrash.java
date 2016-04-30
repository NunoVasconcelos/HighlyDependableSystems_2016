package test;

import file_system.exceptions.DifferentTimestampException;
import file_system.exceptions.IntegrityViolationException;
import file_system.fs_library.RmiServerIntf;
import file_system.shared.Block;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
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
import java.util.Hashtable;
import java.util.List;




public class FS_BlockServerByzantineTrash extends UnicastRemoteObject implements RmiServerIntf {
    private Hashtable<String, Block> blocks = new Hashtable<>();
    private List<PublicKey> publicKeys = new ArrayList<>();
    private static String connString;
    private static Registry rmiRegistry;
    private static int port;
    private static SecretKey sharedSecret;

    public FS_BlockServerByzantineTrash() throws RemoteException {
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
        FS_BlockServerByzantineTrash obj = new FS_BlockServerByzantineTrash();

        // Bind this object instance to the name "RmiServer"
        connString = "//localhost/RmiServer" + args[0];
        Naming.rebind(connString, obj);
        System.out.println("PeerServer bound in registry");
    }

    public Object serverRequest(byte[] digest, String functionName, ArrayList<Object> args) throws InterruptedException, NoSuchAlgorithmException, DifferentTimestampException, IntegrityViolationException, IOException, InvalidKeyException {
        return new ArrayList<>();
    }
}