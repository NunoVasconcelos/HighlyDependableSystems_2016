package client;

import file_system.IntegrityViolationException;
import file_system.fs_library.FS_Library;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.List;

public class Client
{
	public static void main(String [] args) throws Exception, IntegrityViolationException {
        FS_Library lib = new FS_Library();

		// init file system: get publicKey from cc
        lib.fs_init();

		// get publicKeys from all users
		List<PublicKey> publicKeys = lib.fs_list();

		// read local file
		Path path = Paths.get(args[0]);
		byte[] content = Files.readAllBytes(path);



		// write content from local file into block server
		int pos = 0;
		int size = content.length-1;
		System.out.println("writing content from file: " + path.toString() + ", pos: " + pos + ", size: " + size);
		lib.fs_write(pos, content);

		// read content from stored file on block server
		pos = 0;
		size = 50;
		System.out.println("reading content from my file: pos: " + pos + ", size: " + size);
		byte[] bytesReturned = lib.fs_read(publicKeys.get(0), pos, size);
		File output = new File("output2.txt");
		FileOutputStream outputStream = new FileOutputStream(output);
		outputStream.write(bytesReturned);
		outputStream.flush();
		outputStream.close();

	}
}
