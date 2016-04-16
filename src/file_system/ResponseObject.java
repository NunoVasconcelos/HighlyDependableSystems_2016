package file_system;

import file_system.PublicKeyBlock;


public class ResponseObject {
    private Block Block;
    private int RID;


    public void setBlock(Block block) {
        this.Block = block;
    }

    public void setRID(int r_id) {
        this.RID = r_id;
    }

    public Block getBlock() {
        return Block;
    }

    public int getRID() {
        return RID;
    }
}
