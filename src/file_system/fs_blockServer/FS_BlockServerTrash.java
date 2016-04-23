package file_system.fs_blockServer;

import file_system.*;
import java.net.MalformedURLException;
import java.rmi.*;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class FS_BlockServerTrash extends UnicastRemoteObject implements RmiServerIntf {

    private static String connString;
    private static int port;

    public FS_BlockServerTrash() throws RemoteException {
        super(0);    // required to avoid the 'rmic' step, see below
    }

    public static void main(String args[]) throws RemoteException, MalformedURLException, InterruptedException {
        System.out.println("RMI server started");

        try { //special exception handler for registry creation
            port = Integer.parseInt(args[0]);
            LocateRegistry.createRegistry(port);
            System.out.println("java RMI registry created on port " + args[0]);
        } catch (RemoteException e) {
            //do nothing, error means registry already exists
            System.out.println("java RMI registry already exists on port " + args[0]);
        }

        //Instantiate RmiServer
        FS_BlockServer obj = new FS_BlockServer();

        // Bind this object instance to the name "RmiServer"
        connString = "//localhost/RmiServer" + args[0];
        Naming.rebind(connString, obj);
        System.out.println("PeerServer bound in registry");
    }

    public Object serverRequest(byte[] digest, String functionName, ArrayList<Object> args)  {
        return new Object();
    }

    public void stop() {
        // TODO: must stop rmi server
    }
}
