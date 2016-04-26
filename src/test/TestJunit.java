package test;

import file_system.DifferentTimestampException;
import file_system.IntegrityViolationException;
import file_system.fs_blockServer.FS_BlockServer;
import file_system.fs_library.FS_Library;
import file_system.fs_library.QuorumNotVerifiedException;
import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class TestJunit {

    private static List<String> ports = new ArrayList<String>(){
        {
            for(int i = 1101; i >= 900; i--) add(i + "");
        }
    };

    private void writeAndReadAllFile(ArrayList<String> ports) throws IntegrityViolationException, QuorumNotVerifiedException, Exception, DifferentTimestampException {
        FS_Library lib = new FS_Library();

        // init file system: get publicKey from cc
        lib.fs_init(ports);

        // get publicKeys from all users
        //List<PublicKey> publicKeys = lib.fs_list();

        // read local file
        Path path = Paths.get("inputFile.txt");
        byte[] content = Files.readAllBytes(path);

        int pos = 0;
        int size = content.length - 1;

        // write content from local file into block server
        lib.fs_write(pos, content);

        // read content from stored file on block server
        byte[] bytesReturned = lib.fs_read(null, pos, (size + 1));

        assertEquals(new String(content, StandardCharsets.UTF_8), new String(bytesReturned, StandardCharsets.UTF_8));
    }

    private String getPort() {
        ports.remove(0);
        return ports.get(1);
    }



	@Test
	public void all4ServersUpAndWell() throws Exception, IntegrityViolationException, QuorumNotVerifiedException, DifferentTimestampException {
        ArrayList<String> ports = new ArrayList<>();

        FS_BlockServer server1 = new FS_BlockServer();
        ports.add(getPort());
        server1.main(new String[]{ports.get(0)});

        FS_BlockServer server2 = new FS_BlockServer();
        ports.add(getPort());
        server2.main(new String[]{ports.get(1)});

        FS_BlockServer server3 = new FS_BlockServer();
        ports.add(getPort());
        server3.main(new String[]{ports.get(2)});

        FS_BlockServer server4 = new FS_BlockServer();
        ports.add(getPort());
        server4.main(new String[]{ports.get(3)});

        writeAndReadAllFile(ports);
	}
	
	@Test
	public void OneServerDown() throws Exception, QuorumNotVerifiedException, DifferentTimestampException, IntegrityViolationException {
        ArrayList<String> ports = new ArrayList<>();

        FS_BlockServer server1 = new FS_BlockServer();
        ports.add(getPort());
        server1.main(new String[]{ports.get(0)});

        FS_BlockServer server2 = new FS_BlockServer();
        ports.add(getPort());
        server2.main(new String[]{ports.get(1)});

        FS_BlockServer server3 = new FS_BlockServer();
        ports.add(getPort());
        server3.main(new String[]{ports.get(2)});

        writeAndReadAllFile(ports);
	}

    @Test(expected=QuorumNotVerifiedException.class)
    public void TwoServersDown() throws Exception, QuorumNotVerifiedException, DifferentTimestampException, IntegrityViolationException {
        ArrayList<String> ports = new ArrayList<>();

        FS_BlockServer server1 = new FS_BlockServer();
        ports.add(getPort());
        server1.main(new String[]{ports.get(0)});

        FS_BlockServer server2 = new FS_BlockServer();
        ports.add(getPort());
        server2.main(new String[]{ports.get(1)});

        writeAndReadAllFile(ports);

    }

    @Test
    public void OneByzantineTrash() throws Exception, QuorumNotVerifiedException, DifferentTimestampException, IntegrityViolationException {
        fail();
    }

    @Test(expected=QuorumNotVerifiedException.class)
    public void TwoByzantineTrash() throws Exception, QuorumNotVerifiedException, DifferentTimestampException, IntegrityViolationException {
    }
   
}
