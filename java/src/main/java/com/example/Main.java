package com.example;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;


public class Main {
    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            RSAPrivateKey privateKey = getRSAPrivateKey("../keys/private-key-encrypted.pem", "passphrase");
            Algorithm algorithm = Algorithm.RSA256(null, privateKey);
            String token = JWT.create()
                    .withKeyId("key-id-1")
                    .withSubject("1234567890")
                    .withClaim("name", "John Doe")
                    .withClaim("admin", true)
                    .sign(algorithm);

            System.out.println(token);
        } catch (JWTCreationException exception) {
            System.err.println("Could not create token");
            exception.printStackTrace(System.err);
        } catch (IOException exception) {
            System.err.println("Could not load private key");
            exception.printStackTrace(System.err);
        }
    }
    private static RSAPrivateKey getRSAPrivateKey(String fileName, String passphrase) throws IOException {
        PEMParser pemParser = new PEMParser(new FileReader(new File(fileName)));
        PEMEncryptedKeyPair pemEncryptedKeyPair = (PEMEncryptedKeyPair) pemParser.readObject();
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(passphrase.toCharArray());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair kp = converter.getKeyPair(pemEncryptedKeyPair.decryptKeyPair(decProv));
        return (RSAPrivateKey) kp.getPrivate();
    }
}
