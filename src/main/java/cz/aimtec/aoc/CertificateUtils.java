package cz.aimtec.aoc;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public final class CertificateUtils {

    private CertificateUtils() {
    }

    public static String getFirstMatchingEntryAlias(KeyStore keyStore, Class<? extends KeyStore.Entry> entryClass) throws Exception {
        for (Enumeration<String> aliasesEnumeration = keyStore.aliases(); aliasesEnumeration.hasMoreElements(); ) {
            String alias = aliasesEnumeration.nextElement();

            if (keyStore.entryInstanceOf(alias, entryClass)) {
                return alias;
            }
        }
        return null;
    }

    public static X509Certificate getCaCertificate(KeyStore.PrivateKeyEntry privateKeyEntry) {
        Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
        int chainLength = certificateChain.length;

        if (chainLength > 0) {
            Certificate certificate = certificateChain[chainLength - 1];

            if (certificate instanceof X509Certificate) {
                X509Certificate x509Certificate = (X509Certificate) certificate;

                if (isSelfSigned(x509Certificate)) {
                    return x509Certificate;
                }
            }
        }

        return null;
    }

    public static boolean isSelfSigned(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
    }

    public static String getAliasFor(X509Certificate certificate) {
        String distinguishedName = certificate.getSubjectX500Principal().getName();

        try {
            String commonName = getAttributeValue(distinguishedName, "CN");

            if (commonName != null) {
                return commonName;
            }
        } catch (NamingException ignore) {
        }

        return distinguishedName;
    }

    public static String getAttributeValue(String distinguishedName, String attributeName) throws NamingException {
        for (Rdn rdn : new LdapName(distinguishedName).getRdns()) {
            for (NamingEnumeration<? extends Attribute> attributeEnumeration = rdn.toAttributes().getAll(); attributeEnumeration.hasMore(); ) {
                Attribute attribute = attributeEnumeration.next();

                if (attributeName.equalsIgnoreCase(attribute.getID())) {
                    for (NamingEnumeration<?> valueEnumeration = attribute.getAll(); valueEnumeration.hasMore(); ) {
                        Object value = valueEnumeration.next();

                        if (value != null) {
                            valueEnumeration.close();
                            attributeEnumeration.close();
                            return value.toString();
                        }
                    }
                }
            }
        }
        return null;
    }

}
