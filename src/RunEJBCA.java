
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.ejbca.core.protocol.ws.client.gen.*;
import org.ejbca.core.protocol.ws.common.CertificateHelper;


import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.List;

public class RunEJBCA {
    public static void main(String[] args) throws Exception {
        /**
         * Connect to functions: WebServiceConnection, WebClient, User
         **/
        WebServiceConnection connection = new WebServiceConnection();
        WebClient client = new WebClient();
        User user = new User();

        // Declare UserDataVOWS of EJBCA
        UserDataVOWS userDataVOWS = new UserDataVOWS();

        /**
         * Connect EJBCA RA
         * <p>
         * Connect to server virtual machine with URL (Change in host file)
         * Select trustsstore.jks & superadmin.p12
         * Follow: https://download.primekey.com/docs/EJBCA-Enterprise/6_15_2/Web_Service_Interface.html
         **/
        String urlstr = "https://caadmin.cmc.vn:8443/ejbca/ejbcaws/ejbcaws?wsdl";
        String truststore = "src\\p12\\truststore.jks";
        String passTruststore = "123456";
        String superadmin = "src\\p12\\superadmin.p12";
        String passSuperadmin = "123456";
        EjbcaWS ejbcaraws = connection.connectService(urlstr, truststore, passTruststore, superadmin, passSuperadmin);

        /**
         * GEt Version
         **/
        System.out.println("EJBCA Version: " + ejbcaraws.getEjbcaVersion());

        /**
         * Get end entity
         **/
        connection.getEndEntity(ejbcaraws);

        /**
         * Get available CA
         **/
        connection.getAvailableCA(ejbcaraws);

        /**
         * Add or Edit user
         **/
        user.addOrEditUser(userDataVOWS, ejbcaraws,
                "ngmduc4",
                "1",
                false,
                "CN=ngmduc4, OU=CMC, O=CMC company, L=ha noi, ST=cau giay, C=VN",
                "ServerCA",
                UserDataVOWS.TOKEN_TYPE_USERGENERATED,
                EndEntityConstants.STATUS_GENERATED,
                null,
                null,
                "EndEntityProfile",
                "EndEntityCertificateProfile",
                null
        );

        /**
         * Find users
         **/
        List<UserDataVOWS> result = user.findUsers(ejbcaraws, "ServerCA", UserMatch.MATCH_WITH_CA);
        user.showUser(result);

        /**
         * Delete user
         **/
//        user.deleteUser(ejbcaraws, "nmduc16", RevokeStatus.REVOKATION_REASON_CERTIFICATEHOLD, true);
//        result = user.findUsers(ejbcaraws, "ServerCA", UserMatch.MATCH_WITH_CA);
//        user.showUser(result);

        /**
         * Create Certificate Respond from File
         **/
        CertificateResponse certificateResponse = connection.certificateRequestFromFile(ejbcaraws,
                Paths.get("src\\example\\ngmduc4.csr"),
                user.findUserByUserName(ejbcaraws, "ngmduc4"),
                CertificateHelper.CERT_REQ_TYPE_PKCS10,
                null,
                CertificateHelper.RESPONSETYPE_CERTIFICATE);
        connection.showCertificateRespond(certificateResponse);

        /**
         * Find certificate
         **/
//        List<Certificate> listCerts = connection.findCerts(ejbcaraws, "ngmduc4", false);
//        connection.showCertificate(listCerts);
//        System.out.println("size: " + listCerts.size());

        /**
         * Revoke Certificate
         **/
//        connection.revokeCertificate(ejbcaraws, listCerts.get(39),RevokeStatus.REVOKATION_REASON_UNSPECIFIED);
//        listCerts = connection.findCerts(ejbcaraws, "ngmduc4", true);
//        connection.showCertificate(listCerts);
//        System.out.println("size: " + listCerts.size());

        /**
         * Check Revokation
         **/
//        connection.checkRevokation(ejbcaraws, listCerts.get(39));

        /**
         * Generate P12 KeyStore
         **/
//        user.addOrEditUser(userDataVOWS, ejbcaraws,
//                "client2",
//                "1",
//                false,
//                "CN=client2, OU=CMC, O=CMC company, L=ha noi, ST=cau giay, C=VN",
//                "ServerCA",
//                UserDataVOWS.TOKEN_TYPE_P12, //have to setup P12
//                EndEntityConstants.STATUS_NEW, //have to setup NEW
//                null,
//                null,
//                "EndEntityProfile",
//                "EndEntityCertificateProfile",
//                null
//        );
//        KeyStore p12Req = connection.pkcs12Req(ejbcaraws, "client2", "1", null , "2048", AlgorithmConstants.KEYALGORITHM_RSA);

        /**
         * Generate Certificate from P12"
         **/
//        connection.certificateFromP12(p12Req,"PKCS12", "1");


        /**
         * Soft Token Request
         **/
//        connection.softTokenRequest(ejbcaraws, user.setUser(
//                userDataVOWS,
//                ejbcaraws,
//                "client5",
//                "1",
//                true, //have to setup default password
//                "CN=client5, OU=CMC, O=CMC company, L=ha noi, ST=cau giay, C=VN",
//                "ServerCA",
//                UserDataVOWS.TOKEN_TYPE_P12,  //have to setup P12
//                EndEntityConstants.STATUS_NEW, //have to setup NEW
//                null,
//                null,
//                "EndEntityProfile",
//                "EndEntityCertificateProfile",
//                null
//                ), null, "2048", AlgorithmConstants.KEYALGORITHM_RSA);

        /**
         * Generate Key
         **/
        KeyPair keys = connection.generateKeys("2048" , AlgorithmConstants.KEYALGORITHM_RSA);

        /**
         * Generate Request PKCS10
         **/
//                user.addOrEditUser(userDataVOWS, ejbcaraws,
//                "client6",
//                "1",
//                false,
//                "CN=client6, OU=CMC, O=CMC company, L=ha noi, ST=cau giay, C=VN",
//                "ServerCA",
//                UserDataVOWS.TOKEN_TYPE_USERGENERATED,
//                EndEntityConstants.STATUS_NEW,
//                null,
//                null,
//                "EndEntityProfile",
//                "EndEntityCertificateProfile",
//                null
//        );
//        PKCS10CertificationRequest pkcs10 = client.pkcs10CertificationRequest("SHA1WithRSA", "CN=client6, OU=CMC, O=CMC company, L=ha noi, ST=cau giay, C=VN", keys);

        /**
         * Get certificate respond from pkcs 10 request
         **/
//        CertificateResponse certenv = connection.certificateRequestFromP10(ejbcaraws,pkcs10,"client6", "1", null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
//        connection.showCertificateRespond(certenv);


    }
}
