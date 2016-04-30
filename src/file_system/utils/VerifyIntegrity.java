package file_system.utils;

import file_system.exceptions.IntegrityViolationException;
import file_system.shared.PublicKeyBlock;

import java.security.PublicKey;
import java.util.List;

public final class VerifyIntegrity {

    public static void verify(PublicKeyBlock publicKeyBlock, byte[] signature, PublicKey publicKey) throws IntegrityViolationException {
        List<String> contentHashBlockIds = publicKeyBlock.getContentHashBlockIds();
        String concatenatedIds = "";
        for(String contentId : contentHashBlockIds) concatenatedIds += contentId;

        if(!DigitalSignature.verifySign(concatenatedIds.getBytes(), signature, publicKey))
            throw new IntegrityViolationException();
    }
}
