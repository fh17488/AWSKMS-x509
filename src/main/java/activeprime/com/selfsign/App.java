package activeprime.com.selfsign;

import java.io.BufferedWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * Hello world!
 *
 */
public class App {

    public static void main(String[] args) {
        String keyId = "f5413718-0ebd-44e6-ba9c-4700dea0b5ab";
        String commonName = "com.farazhaider";
        String certificateFile = "public-cert.pem";
        try {
            generateSelfSignedCertificate(keyId, commonName, certificateFile);
            System.out.println("wrote certificate to file");
        } catch (GeneralSecurityException secExcep) {
            System.out.println(secExcep.getMessage());
        } catch (IOException ioExcep) {
            System.out.println(ioExcep.getMessage());
        }
    }

    public static void generateSelfSignedCertificate(String keyId, String commonName, String certificateFile)
            throws IOException, GeneralSecurityException {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, commonName).build();
        // X500Name dnName = new X500Name(subjectDN);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now));

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1);

        Date endDate = calendar.getTime();

        PublicKey publicKey = null;
        SigningAlgorithmSpec signingAlgorithmSpec = null;
        try (KmsClient kmsClient = KmsClient.create()) {
            GetPublicKeyResponse response = kmsClient.getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build());
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(response.publicKey().asByteArray());
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            publicKey = converter.getPublicKey(spki);
            List<SigningAlgorithmSpec> signingAlgorithms = response.signingAlgorithms();
            if (signingAlgorithms != null && !signingAlgorithms.isEmpty())
                signingAlgorithmSpec = signingAlgorithms.get(0);
        }
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate,
                endDate, dnName, publicKey);

        ContentSigner contentSigner = new AwsKmsContentSigner(keyId, signingAlgorithmSpec);

        BasicConstraints basicConstraints = new BasicConstraints(true);
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
                .getCertificate(certBuilder.build(contentSigner));

        Path certFile = Paths.get("./"+certificateFile);
        try (BufferedWriter writer = Files.newBufferedWriter(certFile, StandardCharsets.UTF_8);
                PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
        }

        return;
    }
}
