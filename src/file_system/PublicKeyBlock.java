package file_system;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PublicKeyBlock extends Block implements Serializable {
    private List<String> contentHashBlockIds = new ArrayList<>();
    private byte[] signature;
    private String timestamp;

    public List<String> getContentHashBlockIds()
    {
        return this.contentHashBlockIds;
    }

    public byte[] getSignature() { return this.signature; }

    public String getTimestamp() { return timestamp; }

    public void setContentHashBlockIds(List<String> contentHashBlockIds, byte[] signature, String timestamp)
    {
        this.contentHashBlockIds = contentHashBlockIds;
        this.signature = signature;
        this.timestamp = timestamp;
    }

    @Override
    public int hashCode() {
        int hashCode;
        if(signature != null && timestamp != null) hashCode = contentHashBlockIds.hashCode() + Arrays.hashCode(signature) + timestamp.hashCode();
        else hashCode = contentHashBlockIds.hashCode();
        return hashCode;
    }
}
