package client;

import file_system.DifferentTimestampException;
import file_system.IntegrityViolationException;
import file_system.fs_library.FS_Library;
import file_system.fs_library.QuorumNotVerifiedException;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.List;

public class Client
{
	public static void main(String [] args) throws Exception, IntegrityViolationException, QuorumNotVerifiedException, DifferentTimestampException {
		FS_Library lib = new FS_Library();

		// init file system: get publicKey from cc
		lib.fs_init();

		// get publicKeys from all users
		List<PublicKey> publicKeys = lib.fs_list();

		// read local file
		Path path = Paths.get("inputFile.txt");
		byte[] content = Files.readAllBytes(path);

		int pos = 0;
		int size = content.length-1;

		// write content from local file into block server
		lib.fs_write(pos, content);

		// read content from stored file on block server
		byte[] bytesReturned = lib.fs_read(null, pos, (size+1));
		File output = new File("output2.txt");
		FileOutputStream outputStream = new FileOutputStream(output);
		outputStream.write(bytesReturned);
		outputStream.flush();
		outputStream.close();

	}
}
