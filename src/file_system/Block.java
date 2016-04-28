package file_system;

import java.time.LocalDateTime;

abstract public class Block {
    protected int timestamp = 0;

    public int getTimestamp() { return timestamp; }

    public void incrementTS() { timestamp++; }

}
