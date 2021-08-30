import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;


import java.security.KeyPair;

public class WebClient {

    /**
     * Generate PKCS10 Request
     **/
    PKCS10CertificationRequest pkcs10CertificationRequest(String signatureAlgorithm, String dn, KeyPair keys) throws Exception {
        try {
            PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(signatureAlgorithm, X509Name.getInstance(CertTools.stringToBcX500Name(dn)), keys.getPublic(),
                    new DERSet(), keys.getPrivate());
            System.out.println("pkcs10: "+ pkcs10);
            return pkcs10;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
