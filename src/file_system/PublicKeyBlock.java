package file_system;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class PublicKeyBlock extends Block implements Serializable {
    private List<String> contentHashBlockIds = new ArrayList<>();
    private byte[] signature;

    public List<String> getContentHashBlockIds()
    {
        return this.contentHashBlockIds;
    }

    public byte[] getSignature()
    {
        return this.signature;
    }

    public void setContentHashBlockIds(List<String> contentHashBlockIds, byte[] signature)
    {
        this.contentHashBlockIds = contentHashBlockIds;
        this.signature = signature;
    }
}
