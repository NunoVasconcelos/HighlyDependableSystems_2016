package file_system.fs_library;

import file_system.exceptions.DifferentTimestampException;
import file_system.exceptions.IntegrityViolationException;

import java.io.IOException;
import java.rmi.Remote;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public interface RmiServerIntf extends Remote {
    Object serverRequest(byte[] digest, String functionName, ArrayList<Object> args) throws IOException, InterruptedException, NoSuchAlgorithmException, DifferentTimestampException, IntegrityViolationException, InvalidKeyException;
}
