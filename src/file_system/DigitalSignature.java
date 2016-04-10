package file_system;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public final class DigitalSignature {

    public static boolean verifySign(byte[] data, byte[] signature, PublicKey public_key) {
        boolean verifies = false;
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(public_key.getEncoded());
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey =
                    keyFactory.generatePublic(pubKeySpec);
            java.security.Signature sig = java.security.Signature.getInstance("SHA1withRSA");
            sig.initVerify(pubKey);

            // Input data to be verified
            sig.update(data);

            // verify signature
            verifies = sig.verify(signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return verifies;
    }
}
