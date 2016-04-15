package file_system;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class PublicKeyBlock extends Block implements Serializable {
    private List<String> contentHashBlockIds = new ArrayList<>();
    private byte[] signature;
    private LocalDateTime timestamp;

    public PublicKeyBlock() { this.timestamp = LocalDateTime.now(); }

    public List<String> getContentHashBlockIds()
    {
        return this.contentHashBlockIds;
    }

    public byte[] getSignature() { return this.signature; }

    public LocalDateTime getTimestamp() { return timestamp; }

    public void setContentHashBlockIds(List<String> contentHashBlockIds, byte[] signature, LocalDateTime timestamp)
    {
        this.contentHashBlockIds = contentHashBlockIds;
        this.signature = signature;
        this.timestamp = timestamp;
    }
}
