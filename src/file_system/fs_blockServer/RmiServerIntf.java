package file_system.fs_blockServer;

import file_system.Block;
import file_system.IntegrityViolationException;
import file_system.OldTimestampException;
import file_system.PublicKeyBlock;
import sun.security.rsa.RSAPublicKeyImpl;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;


public interface RmiServerIntf extends Remote {
    Block get(String id) throws RemoteException;
    String put_k(PublicKeyBlock data, byte[] signature, RSAPublicKeyImpl public_key) throws RemoteException, NoSuchAlgorithmException, IntegrityViolationException, OldTimestampException;
    String put_h(byte[] data) throws RemoteException, NoSuchAlgorithmException;
    List<PublicKey> readPublicKeys() throws RemoteException;
    void storePubKey(RSAPublicKeyImpl p) throws RemoteException;
}
