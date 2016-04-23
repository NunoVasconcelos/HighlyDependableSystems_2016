package test;

import file_system.DifferentTimestampException;
import file_system.IntegrityViolationException;
import file_system.fs_blockServer.FS_BlockServer;
import file_system.fs_blockServer.FS_BlockServerTrash;
import file_system.fs_library.FS_Library;
import file_system.fs_library.QuorumNotVerifiedException;
import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.Assert.assertEquals;

public class TestJunit {

    private void writeAndReadAllFile() throws IntegrityViolationException, QuorumNotVerifiedException, Exception, DifferentTimestampException {
        FS_Library lib = new FS_Library();

        // init file system: get publicKey from cc
        lib.fs_init();

        // get publicKeys from all users
        //List<PublicKey> publicKeys = lib.fs_list();

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

	@Test
	public void all4ServersUpAndWell() throws Exception, IntegrityViolationException, QuorumNotVerifiedException, DifferentTimestampException {

        FS_BlockServer server1099 = new FS_BlockServer();
        server1099.main(new String[]{"1099"});

        FS_BlockServer server1098 = new FS_BlockServer();
        server1098.main(new String[]{"1098"});

        FS_BlockServer server1097 = new FS_BlockServer();
        server1097.main(new String[]{"1097"});

        FS_BlockServer server1096 = new FS_BlockServer();
        server1096.main(new String[]{"1096"});

        writeAndReadAllFile();

        server1099.stop();
        server1098.stop();
        server1097.stop();
        server1096.stop();
	}
	
	@Test
	public void OneServerDown() throws Exception, QuorumNotVerifiedException, DifferentTimestampException, IntegrityViolationException {
        FS_BlockServer server1099 = new FS_BlockServer();
        server1099.main(new String[]{"1099"});

        FS_BlockServer server1098 = new FS_BlockServer();
        server1098.main(new String[]{"1098"});

        FS_BlockServer server1097 = new FS_BlockServer();
        server1097.main(new String[]{"1097"});

        writeAndReadAllFile();

        server1099.stop();
        server1098.stop();
        server1097.stop();
	}

    @Test(expected=QuorumNotVerifiedException.class)
    public void TwoServersDown() throws Exception, QuorumNotVerifiedException, DifferentTimestampException, IntegrityViolationException {
        FS_BlockServer server1099 = new FS_BlockServer();
        server1099.main(new String[]{"1099"});

        FS_BlockServer server1098 = new FS_BlockServer();
        server1098.main(new String[]{"1098"});

        try {
            writeAndReadAllFile();
        } catch (QuorumNotVerifiedException e) {
            server1099.stop();
            server1098.stop();
            throw e;
        }
    }

    @Test
    public void OneByzantineTrash() throws Exception, QuorumNotVerifiedException, DifferentTimestampException, IntegrityViolationException {
        FS_BlockServer server1099 = new FS_BlockServer();
        server1099.main(new String[]{"1099"});

        FS_BlockServer server1098 = new FS_BlockServer();
        server1098.main(new String[]{"1098"});

        FS_BlockServer server1097 = new FS_BlockServer();
        server1097.main(new String[]{"1097"});

        // byzantine
        FS_BlockServerTrash server1096 = new FS_BlockServerTrash();
        server1096.main(new String[]{"1096"});

        writeAndReadAllFile();

        server1099.stop();
        server1098.stop();
        server1097.stop();
        server1096.stop();
    }

    @Test(expected=QuorumNotVerifiedException.class)
    public void TwoByzantineTrash() throws Exception, QuorumNotVerifiedException, DifferentTimestampException, IntegrityViolationException {
        FS_BlockServer server1099 = new FS_BlockServer();
        server1099.main(new String[]{"1099"});

        FS_BlockServer server1098 = new FS_BlockServer();
        server1098.main(new String[]{"1098"});


        // byzantine
        FS_BlockServerTrash server1097 = new FS_BlockServerTrash();
        server1097.main(new String[]{"1097"});

        FS_BlockServerTrash server1096 = new FS_BlockServerTrash();
        server1096.main(new String[]{"1096"});

        try {
            writeAndReadAllFile();
        } catch (QuorumNotVerifiedException e) {
            server1099.stop();
            server1098.stop();
            server1097.stop();
            server1096.stop();
            throw e;
        }
    }
   
}
