package file_system.fs_blockServer;

/**
 * Created by andre on 02/03/2016.
 */
import file_system.Block;
import file_system.PublicKeyBlock;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;


public interface RmiServerIntf extends Remote {
    public Block get(String id) throws RemoteException;
    public String put_k(PublicKeyBlock data, byte[] signature, PublicKey public_key) throws RemoteException, NoSuchAlgorithmException;
    public String put_h(byte[] data) throws RemoteException, NoSuchAlgorithmException;
    public List<PublicKey> readPublicKeys() throws RemoteException;
    public void storePubKey(PublicKey p) throws RemoteException;
}
