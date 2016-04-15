package test;

import file_system.IntegrityViolationException;
import file_system.fs_library.FS_Library;
import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.List;
import static org.junit.Assert.assertEquals;

public class TestJunit {

	@Test
	public void writeAndReadAllFile() throws Exception, IntegrityViolationException {
		   
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
		
		assertEquals(new String(content, StandardCharsets.UTF_8), new String(bytesReturned, StandardCharsets.UTF_8));
	}
	
//	@Test
//	public void writeAndReadPartOfFile() throws Exception {
//
//		FS_Library lib = new FS_Library();
//
//		// init file system: get publicKey from cc
//		lib.fs_init();
//
//		// get publicKeys from all users
//		List<PublicKey> publicKeys = lib.fs_list();
//
//		// read local file
//		Path path = Paths.get("inputFile.txt");
//		byte[] content = Files.readAllBytes(path);
//
//		int pos = 0;
//		int size = content.length-1;
//
//		// write content from local file into block server
//		lib.fs_write(pos, content);
//
//		// read part of the content from stored file on block server
//		pos = (content.length-1/4);
//		size = (content.length-1/2);
//		byte[] bytesReturned = lib.fs_read(publicKeys.get(0), pos, (size+1));
//
//		assertFalse(new String(content, StandardCharsets.UTF_8).equals(new String(bytesReturned, StandardCharsets.UTF_8)));
//	}
   
}
