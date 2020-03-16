package cz.aimtec.poc;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class Client {

    public static void main(String[] args) throws Exception {
        char[] password = "Just159357".toCharArray();
        // load the PKCS12 key store
        KeyStore keyStore = loadKeyStore(
            "PKCS12",
            new FileInputStream(new File(System.getProperty("user.home"), "Downloads/VCA12015605_Export_Pošta_New_Linka_Just159357.pfx")),
            password
        );
        // find the first private key entry in the store
        String privateKeyEntryAlias = CertificateUtils.getFirstMatchingEntryAlias(keyStore, KeyStore.PrivateKeyEntry.class);

        if (privateKeyEntryAlias == null) {
            throw new IllegalStateException("No private key entry found in the key store.");
        }

        // get the CA (self signed) certificate from the certificate chain associated with the private key entry
        X509Certificate caCertificate = CertificateUtils.getCaCertificate(
            (KeyStore.PrivateKeyEntry) keyStore.getEntry(privateKeyEntryAlias, new KeyStore.PasswordProtection(password))
        );

        if (caCertificate == null) {
            throw new IllegalStateException("No CA certificate found in the private key's certificate chain.");
        }

        // create an empty trust store
        KeyStore trustStore = loadKeyStore(KeyStore.getDefaultType(), null, null);

        // add the CA certificate to it as a trusted certificate
        trustStore.setCertificateEntry("ca", caCertificate);

//        // re-use the key store as a trust store
//        KeyStore trustStore = keyStore;
//
//        // add the CA certificate to it as a trusted certificate
//        trustStore.setCertificateEntry(CertificateUtils.getAliasFor(caCertificate), caCertificate);

//        // save the trust store into a file
//        saveKeyStore(
//            trustStore,
//            new FileOutputStream(new File(System.getProperty("user.home"), "Downloads/truststore")),
//            password
//        );

        SSLContext sslContext = SSLContexts.custom()
            .loadKeyMaterial(keyStore, password)
            .loadTrustMaterial(trustStore, null)
            .build();

        try (
            CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLContext(sslContext)
                .build();
            CloseableHttpResponse response = httpClient.execute(new HttpGet("https://b2b.postaonline.cz/services/POLService/v1"));
        ) {
            System.out.println(EntityUtils.toString(response.getEntity()));
        }
    }

    private static KeyStore loadKeyStore(String storeType, InputStream keyStoreStream, char[] password) throws Exception {
        try (InputStream autoCloseKeyStoreStream = keyStoreStream) {
            KeyStore keyStore = KeyStore.getInstance(storeType);

            keyStore.load(autoCloseKeyStoreStream, password);

            return keyStore;
        }
    }

    private static void saveKeyStore(KeyStore keyStore, OutputStream keyStoreStream, char[] password) throws Exception {
        try (OutputStream autoCloseKeyStoreStream = keyStoreStream) {
            keyStore.store(autoCloseKeyStoreStream, password);
        }
    }

}
