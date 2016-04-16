package file_system;

import java.time.LocalDateTime;

abstract public class Block {
    protected int timestamp;

    public int getTimestamp() { return timestamp; }
    public void setTimestamp(int timestamp)
    {this.timestamp = timestamp;}
}
