
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jcajce.provider.keystore.PKCS12;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.protocol.ws.client.gen.*;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;


import javax.xml.namespace.QName;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;


public class WebServiceConnection {

    /**
     * Connect to Web Server
     * Follow: https://download.primekey.com/docs/EJBCA-Enterprise/6_15_2/Web_Service_Interface.html
     **/
    public EjbcaWS connectService(String urlstr, String truststore, String passTruststore, String superadmin, String passSuperadmin) throws Exception {
        try {
            CryptoProviderTools.installBCProvider();
            System.setProperty("javax.net.ssl.trustStore", truststore);
            System.setProperty("javax.net.ssl.trustStorePassword", passTruststore);

            System.setProperty("javax.net.ssl.keyStore", superadmin);
            System.setProperty("javax.net.ssl.keyStorePassword", passSuperadmin);

            QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
            EjbcaWSService service = new EjbcaWSService(new URL(urlstr), qname);
            return service.getEjbcaWSPort();
        } catch (Exception exc) {
            System.err
                    .println("*** Could not connect to non-authenticated web service");

            return null;
        }
    }


    /**
     * Get Available CAs
     **/
    public void getAvailableCA(EjbcaWS ejbcaraws) throws Exception {
        System.out.println("\n\n");
        // if no AvailableCA be getted
        if (ejbcaraws.getAvailableCAs().isEmpty()) {
            System.out.println("No Available CAs");
        } else {
            //Show data
            System.out.println(" Available CAs ");
            for (NameAndId i : ejbcaraws.getAvailableCAs()
            ) {
                System.out.println("Name: " + i.getName() + "  (Id: " + i.getId() + ")");
                System.out.println("--------------------------");
            }

        }
    }

    /**
     * Get End Entity Profile
     **/
    public void getEndEntity(EjbcaWS ejbcaraws) throws Exception {
        System.out.println("\n\n");
        // if get no Authorized End Entity Profiles
        if (ejbcaraws.getAuthorizedEndEntityProfiles().isEmpty()) {
            System.out.println("No End Entity Profile");
        } else {
            //Show data
            System.out.println("  End Entity Profile ");
            for (NameAndId i : ejbcaraws.getAuthorizedEndEntityProfiles()
            ) {
                System.out.println("Name: " + i.getName() + "  (Id: " + i.getId() + ")");
                availableCP(ejbcaraws.getAvailableCertificateProfiles(i.getId()));
                availableCA(ejbcaraws.getAvailableCertificateProfiles(i.getId()));
                System.out.println("--------------------------");
            }

        }
    }

    public void availableCP(List<NameAndId> available) {
        if (available.isEmpty()) {
            System.out.println("No Available Certificate Profiles");
        } else {
            for (NameAndId i : available
            ) {
                System.out.println("CP: " + i.getName() + "(id: " + i.getId() + ")");
            }
        }
    }

    public void availableCA(List<NameAndId> available) {
        if (available.isEmpty()) {
            System.out.println("No Available CAs Profiles");
        } else {
            for (NameAndId i : available
            ) {
                System.out.println("CA: " + i.getName() + "(id: " + i.getId() + ")");
            }
        }
    }

    /**
     * Soft token request
     **/
    public org.ejbca.core.protocol.ws.client.gen.KeyStore softTokenRequest(EjbcaWS ejbcaraws, UserDataVOWS userData, java.lang.String hardTokenSN,
                                                                           java.lang.String keyspec, java.lang.String keyalg) throws Exception {
        try {
            KeyStore keyStore = ejbcaraws.softTokenRequest(userData, hardTokenSN, keyspec,
                    keyalg);
            System.out.println("\n\n");
            System.out.println("Soft Token Request: \n" + new String(keyStore.getKeystoreData(), StandardCharsets.UTF_8));
            return keyStore;
        } catch (EjbcaException_Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Certificate Response
     **/
    CertificateResponse certificateRequest(EjbcaWS ejbcaraws, org.bouncycastle.pkcs.PKCS10CertificationRequest requestData, UserDataVOWS userData,
                                                   int requestType,
                                                   java.lang.String hardTokenSN, java.lang.String responseType)
            throws Exception {
        try {
            CertificateResponse certenv = ejbcaraws.certificateRequest(userData, new String(Base64.encode(requestData.getEncoded())),
                    requestType, hardTokenSN, responseType);
            return certenv;
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }
    CertificateResponse certificateRequestFromP10(EjbcaWS ejbcaraws, org.bouncycastle.jce.PKCS10CertificationRequest requestData, String userName, String password,
                                           java.lang.String hardTokenSN, java.lang.String responseType)
            throws Exception {
        try {
            CertificateResponse certenv = ejbcaraws.pkcs10Request(userName, password, new String(Base64.encode(requestData.getEncoded())), hardTokenSN,
                    responseType);
            return certenv;
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }
    CertificateResponse certificateRequestFromFile(EjbcaWS ejbcaraws, Path path, UserDataVOWS userData,
                                                   int requestType,
                                                   java.lang.String hardTokenSN, java.lang.String responseType)
            throws Exception {

        //Declare Function Units
        Units units = new Units();
        //Read data from file
        byte[] request = Files.readAllBytes(path);
        //Convest file to String
        String requestText = new String(request, StandardCharsets.UTF_8);
        //Convest to PKCS10 Certification Request
        org.bouncycastle.pkcs.PKCS10CertificationRequest requestData = units.convertPemToPKCS10CertificationRequest(requestText);
        try {
            CertificateResponse certenv = certificateRequest(ejbcaraws, requestData, userData, requestType, hardTokenSN, responseType);
            return certenv;
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }
    void showCertificateRespond(CertificateResponse certificateResponse) throws Exception  {
        String caString = new String(certificateResponse.getData(), StandardCharsets.UTF_8);
        System.out.println("\n\n");
        System.out.println("Certificate response: \n" + caString);
        System.out.println(certificateResponse.getCertificate().getIssuerX500Principal().getName());
        System.out.println(certificateResponse.getCertificate().getSubjectX500Principal().getName());
    }


    /**
     * pkcs12Req
     **/
    org.ejbca.core.protocol.ws.client.gen.KeyStore pkcs12Req(EjbcaWS ejbcaraws,
                                                             java.lang.String username, java.lang.String password,
                                                             java.lang.String hardTokenSN, java.lang.String keyspec,
                                                             java.lang.String keyalg) throws Exception {
        try {
            KeyStore keyStore = ejbcaraws.pkcs12Req(username, password, hardTokenSN,
                    keyspec, keyalg);
            System.out.println("\n\n");
            System.out.println("keyStore Data (P12): \n" + new String(keyStore.getKeystoreData(), StandardCharsets.UTF_8));
            return keyStore;
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    /**
     * Generate Server Certificate from P12
     **/
    java.security.cert.Certificate certificateFromP12(KeyStore p12Req, String type, String password) throws Exception {
        try {
            java.security.KeyStore ks = KeyStoreHelper.getKeyStore(p12Req.getKeystoreData(), type, password);
            Enumeration<String> en = ks.aliases();
            String alias = en.nextElement();
            java.security.cert.Certificate certificateP12 = (java.security.cert.Certificate) ks.getCertificate(alias);
            //Show certificate
            System.out.println("\n\n");
            System.out.println("Server Certificate from P12:");
            System.out.println("Encoded   : " + String.format("%8s", Integer.toBinaryString(ByteBuffer.wrap(certificateP12.getEncoded()).getInt())));
            System.out.println("Type      : " + certificateP12.getType());
            System.out.println("Public Key: " + certificateP12.getPublicKey());
            return certificateP12;
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Find Certificate
     **/
    java.util.List<Certificate> findCerts(EjbcaWS ejbcaraws, java.lang.String username,
                                          boolean onlyValid) throws Exception {
        try {
            return ejbcaraws.findCerts(username, onlyValid);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    public void showCertificate(List<Certificate> result) {
        System.out.println("\n\n");
        if (result.size() != 0) {
            for (Certificate i :
                    result) {
                System.out.println("Certificate        : " + i.getCertificate());
                System.out.println("CertificateData    : \n" + new String(i.getCertificateData(), StandardCharsets.UTF_8));
                System.out.println("RawCertificateData : " + String.format("%8s", Integer.toBinaryString(ByteBuffer.wrap(i.getRawCertificateData()).getInt()))
                        .replaceAll(" ", "0"));
                System.out.println("KeyStore           : " + i.getKeyStore());
                System.out.println("Type               : " + i.getType());
                System.out.println("=========================================");
            }
        } else {
            System.out.println("No Certificate for search!");
        }
    }

    /**
     * Check Revokation Status
     **/
    RevokeStatus checkRevokationStatus(EjbcaWS ejbcaraws, java.lang.String issuerDN,
                                       java.lang.String certificateSN) throws Exception {
        try {
            return ejbcaraws.checkRevokationStatus(issuerDN, certificateSN);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    void checkRevokation(EjbcaWS ejbcaraws, Certificate cert) {
        try {
            //Generate x509 Certificate
            X509Certificate x509Cert = (X509Certificate) CertTools
                    .getCertfromByteArray(cert.getRawCertificateData());
            RevokeStatus check = checkRevokationStatus(ejbcaraws, x509Cert.getIssuerDN().toString(), CertTools
                    .getSerialNumberAsString(x509Cert));
            System.out.println("\n\n");
            System.out.println("Reason: " + checkReason(check.getReason()));
            System.out.println("IssuerDN: " + check.getIssuerDN());
            System.out.println("Certificate SN: " + check.getCertificateSN());
            System.out.println("Revocation Date: " + check.getRevocationDate());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    String checkReason(int i) {
        if (i == RevokeStatus.NOT_REVOKED) {
            return "NOT_REVOKED";
        } else if (i == RevokeStatus.REVOKATION_REASON_UNSPECIFIED) {
            return "REVOKATION_REASON_UNSPECIFIED";
        } else if (i == RevokeStatus.REVOKATION_REASON_KEYCOMPROMISE) {
            return "REVOKATION_REASON_KEYCOMPROMISE";
        } else if (i == RevokeStatus.REVOKATION_REASON_CACOMPROMISE) {
            return "REVOKATION_REASON_CACOMPROMISE";
        } else if (i == RevokeStatus.REVOKATION_REASON_AFFILIATIONCHANGED) {
            return "REVOKATION_REASON_AFFILIATIONCHANGED";
        } else if (i == RevokeStatus.REVOKATION_REASON_SUPERSEDED) {
            return "REVOKATION_REASON_SUPERSEDED";
        } else if (i == RevokeStatus.REVOKATION_REASON_CESSATIONOFOPERATION) {
            return "REVOKATION_REASON_CESSATIONOFOPERATION";
        } else if (i == RevokeStatus.REVOKATION_REASON_CERTIFICATEHOLD) {
            return "REVOKATION_REASON_CERTIFICATEHOLD";
        } else if (i == RevokeStatus.REVOKATION_REASON_REMOVEFROMCRL) {
            return "REVOKATION_REASON_REMOVEFROMCRL";
        } else if (i == RevokeStatus.REVOKATION_REASON_PRIVILEGESWITHDRAWN) {
            return "REVOKATION_REASON_PRIVILEGESWITHDRAWN";
        } else {
            return "REVOKATION_REASON_AACOMPROMISE";
        }

    }

    /**
     * Revoke Certificate
     **/
    void revokeCert(EjbcaWS ejbcaraws, java.lang.String issuerDN, java.lang.String certificateSN,
                    int reason) throws Exception {
        try {
            ejbcaraws.revokeCert(issuerDN, certificateSN, reason);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    void revokeCertificate(EjbcaWS ejbcaraws, Certificate cert, int reason) throws Exception {
        try {
            //Generate x509 Certificate
            X509Certificate x509Cert = (X509Certificate) CertTools
                    .getCertfromByteArray(cert.getRawCertificateData());

            revokeCert(ejbcaraws, x509Cert.getIssuerDN().toString(), CertTools
                    .getSerialNumberAsString(x509Cert), reason);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate Keys
     **/
    KeyPair generateKeys(String keySpec, String keyalgorithmRsa) throws Exception {
        try {
            KeyPair keys = KeyTools.genKeys(keySpec, keyalgorithmRsa);
            System.out.println("\n\n");
            System.out.println("Private Key: " + keys.getPrivate());
            System.out.println("Public key : " + keys.getPublic());
            return keys;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
