package file_system.shared;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PublicKeyBlock extends Block implements Serializable {
    private List<String> contentHashBlockIds = new ArrayList<>();
    private byte[] signature;

    public List<String> getContentHashBlockIds()
    {
        return this.contentHashBlockIds;
    }

    public byte[] getSignature() { return this.signature; }

    public void setContentHashBlockIds(List<String> contentHashBlockIds, byte[] signature)
    {
        this.contentHashBlockIds = contentHashBlockIds;
        this.signature = signature;
    }

    @Override
    public int hashCode() {
        int hashCode;
        if(signature != null) hashCode = contentHashBlockIds.hashCode() + Arrays.hashCode(signature) + timestamp;
        else hashCode = contentHashBlockIds.hashCode() + timestamp;
        return hashCode;
    }
}
