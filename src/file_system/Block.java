package file_system;

import java.time.LocalDateTime;

abstract public class Block {
    protected int timestamp;

    //TODO we need to implement the getHigherTimestamp() in blockserver (on put_k and put_h)

    public int getTimestamp() { return timestamp; }
    public void setTimestamp(int timestamp)
    {this.timestamp = timestamp;}
}
