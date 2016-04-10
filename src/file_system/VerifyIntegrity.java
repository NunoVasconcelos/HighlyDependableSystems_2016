package file_system;

import java.security.PublicKey;
import java.util.List;

public final class VerifyIntegrity {

    public static void verify(PublicKeyBlock publicKeyBlock, byte[] signature, PublicKey publicKey) throws IntegrityViolationException {
        List<String> contentHashBlockIds = publicKeyBlock.getContentHashBlockIds();
        String concatenatedIds = "";
        for(String contentId : contentHashBlockIds) concatenatedIds += contentId;
        concatenatedIds += publicKeyBlock.getTimestamp();
        if(!DigitalSignature.verifySign(concatenatedIds.getBytes(), signature, publicKey))
            throw new IntegrityViolationException();
    }
}
