# WebID-TLS on JSSE

This Maven Java library implements [WebID-TLS](https://www.w3.org/2005/Incubator/webid/spec/tls/) via the [Java Secure Socket Extension API](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html).

WebID-TLS is an authentication mechanism during the SSL handshake, using client self-signed certificates.  The server asks for a client-provided certificate, which includes a [Web ID](https://www.w3.org/2005/Incubator/webid/spec/identity/) URI.  The URI is followed to the corresponding Web ID Profile. If the server can [verify](https://www.w3.org/2005/Incubator/webid/spec/tls/#verifying-the-webid-claim) the Web ID Profile contains a copy of the public key used in the client certificate, the user is authenticated.

![WebID-TLS Authentication Diagram](https://www.w3.org/2005/Incubator/webid/spec/tls/img/WebIDSequence-friendly.png)

**Note:** Only RSA-based certificates are supported at this time.  The public key is [specified](https://www.w3.org/2005/Incubator/webid/spec/tls/#the-webid-profile-document) in the WebID Profile using the [Cert Ontology](https://www.w3.org/ns/auth/cert#), which only details [RSA Public Key](https://www.w3.org/ns/auth/cert#RSAPublicKey) properties to the level of detail needed for verification.

This library is under active development, but it should stabilize soon.

Dependency | Version | Notes
---------- | ------- | -------
Java SE    | 8 | [Significant Security Enhancements](https://docs.oracle.com/javase/8/docs/technotes/guides/security/enhancements-8.html)
[BouncyCastle](http://bouncycastle.org/java.html) | 1.61 | Used to create self-signed certificates.
[Apache Jena](https://jena.apache.org/) | 3.10.0 | Used to verify a client-provided certificate matches the WebID Profile.

This library contains a few separate pieces:

### Provider
A [JSSE Provider](https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html) which can be used to initialize a [TrustManager](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#TrustManager) which implements the verification scheme described above.

**Note:** This class is under active development, as there are [extensive steps](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html) in creating a custom JSSE `Provider`.

### SniAndCertDnsKeyManager

A [KeyManager](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#KeyManager) which implements [SNI](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#SNIExtension) and [DNS Subject Alternative Names](http://blog.differentpla.net/blog/2013/03/24/bouncy-castle-subject-alternative-names/#use-a-subject-alternative-name-extension) to allow the server to serve multiple DNS host names.

### WebIdTrustManager

This is the [TrustManager](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#TrustManager) which verifies client certificates using WebID-TLS.  The same package also defines `WebIdTrustManagerFactory`, which is a [TrustManagerFactory](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#TrustManagerFactory) to instantiate the `WebIdTrustManager` through the JSSE API.

### WebIdSSLEngineBuilder

This builds an [SSLEngine](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#SSLEngine) with the WebID Trust Manager, `SniAndCertDnsKeyManager`, and specific `SSLEngine` options to facilitate a secure server.

### WebIdX509CertificateBuilder

This class [creates self-signed certificates](https://www.w3.org/2005/Incubator/webid/spec/tls/#certificate-creation) that can be used for WebID-TLS.  All of them will share the same self-signed issuer certificate, which is constructed using the `WebIdX509CertificateBuilderFactory`.  The issuer will have an X.500 Principal of `CN=WebID, O={}`, to give the server the option to [only accept WebID certificates](https://www.w3.org/2005/Incubator/webid/spec/tls/#certificate-example).  This is not required by the specification yet, but the `WebIdTrustManager` (and its factory) require it by default.

## Using the WebIdX509CertificateBuilder

The following code constructs an `X509Certificate` adhering to the WebID specification with a WebID URI of `http://www.example.com/mikepigott#map`:

```java
    import java.security.KeyPair;
    import java.security.KeyPairGenerator;
    import java.security.SecureRandom;
    import java.security.Security;
    import java.security.cert.X509Certificate;
    import java.security.interfaces.RSAPublicKey;

    import org.bouncycastle.jce.provider.BouncyCastleProvider;

    import com.ironhorsesoftware.jsse.webid.certs.WebIdX509CertificateBuilder;
    import com.ironhorsesoftware.jsse.webid.certs.WebIdX509CertificateBuilderFactory;


    // Sets up the BouncyCastle library.
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    final SecureRandom rng = new SecureRandom();

    final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
    keyGen.initialize(2048, rng);

    // Creates the self-signed root WebID certificate, with X.500 Principal CN=WebID, O={}.
    final KeyPair webIdRootKeyPair = keyGen.generateKeyPair();

    final WebIdX509CertificateBuilderFactory factory = new WebIdX509CertificateBuilderFactory(webIdRootKeyPair);

    // Creates the X509Certificate for use with the client.
    final KeyPair webIdClientKeyPair = keyGen.generateKeyPair();

    final WebIdX509CertificateBuilder builder = factory.newCertificateBuilder();
    builder.setCommonName("Michael Pigott");
    builder.setPublicKey((RSAPublicKey) webIdClientKeyPair.getPublic());
    builder.addWebId(new URI("http://www.example.com/mikepigott#map"));
    builder.setYearsValid(1);

    final X509Certificate webIdCert = builder.build();
```

### Creating the Public Key in the Browser

The [recommended way](https://www.w3.org/2005/Incubator/webid/spec/tls/#certificate-creation) to collect a public key from the browser is using the `<keygen>` tag.  However, that tag is [deprecated](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/keygen) and only reliable on a few browsers, most notably Firefox.  If you choose to use it, BouncyCastle provides the [JcaSignedPublicKeyAndChallenge class](http://bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/mozilla/jcajce/JcaSignedPublicKeyAndChallenge.html) which can read that field from the HTTP request (after it has been Base-64 decoded).  The `WebIdX509CertificateBuilder` will accept a `JcaSignedPublicKeyAndChallenge` instance as a parameter for the public key.

### Storing the Self-Signed Root WebID Certificate in a KeyStore for Reuse

It is possible to construct a single self-signed root certificate, and reuse it later.  The following code shows how:

```java
    import java.security.KeyPair;
    import java.security.KeyStore;
    import java.security.cert.X509Certificate;

    import com.ironhorsesoftware.jsse.webid.certs.WebIdX509CertificateBuilderFactory;


    // Construct the WebID root certificate in the first factory.
    final KeyPair webIdRootKeyPair = ...;
    final WebIdX509CertificateBuilderFactory firstFactory = new WebIdX509CertificateBuilderFactory(webIdRootKeyPair);

    // Store the certificate in a KeyStore.
    final String alias = "WebID";
    final char[] password = "password".toCharArray();
    final X509Certificate certificate = firstFactory.getWebIdRootCertificate();

    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, password);
    keyStore.setKeyEntry(alias, webIdRootKeyPair.getPrivateKey(), password, new X509Certificate[] { certificate });

    // Construct a second factory and reuse the certificate.
    final WebIdX509CertificateBuilderFactory secondFactory = new WebIdX509CertificateBuilderFactory(keyStore, alias, password);
```

## Using the WebIdX509TrustManager

The following code will use the `webIdCert` created in the previous example to verify the certificate.

```java
    import java.security.cert.X509Certificate;
    import javax.net.ssl.TrustManager;
    import com.ironhorsesoftware.jsse.webid.tls.WebIdTrustManagerFactory;
    import com.ironhorsesoftware.jsse.webid.tls.WebIdTrustManager;


    final WebIdTrustManagerFactory tmFactory = new WebIdTrustManagerFactory();
    final TrustManager[] trustManagers = tmFactory.getTrustManagers();
    final WebIdTrustManager trustManager = (WebIdTrustManager) trustManagers[0];

    final X509Certificate[] certificateChain = new X509Certificate[]{ webIdCert, factory.getWebIdRootCertificate() };
    trustManager.checkClientTrusted(certificateChain, "RSA");
```

**Note:** This code, on its own, will fail validation.  The `WebIdTrustManager` will try to follow http://www.example.com/mikepigott ([without the #map fragment](https://www.w3.org/2005/Incubator/webid/spec/tls/#verifying-the-webids)) and find nothing there.  We can preload this by initializing the `WebIdTrustManagerFactory` with a `KeyStore`:

```java
    import java.security.KeyStore;


    final char[] keyStorePassword = "password".toCharArray();
    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, keyStorePassword);
    keyStore.setCertificateEntry("http://www.example.com/mikepigott#map", webIdCert);

    final WebIdTrustManagerFactory tmFactory = new WebIdTrustManagerFactory();
    tmFactory.init(keyStore);

    // Retriving the TrustManagers and verifying the certificate chain is done the same as above.
```

## WebIdSSLEngineBuilder

This is the last stop on our tour.  The `WebIdSSLEngineBuilder` configures a TLS-based `SSLEngine` for use with the `WebIdTrustManager` and enhanced PKIX key management.  [PKIX](http://ospkibook.sourceforge.net/docs/OSPKI-2.4.6/OSPKI/pkix-overview.htm) refers to the Certificate-Authority-based system most commonly used today for SSL-based handshake authentication.  The two enhancements allow the TLS `SSLEngine` to serve multiple domain names:

* [Server Name Indication](https://tools.ietf.org/html/rfc6066#page-6) allows the client to tell the server what DNS host it was trying to reach during the TLS handshake.
* [Subject Alternative Names](http://blog.differentpla.net/blog/2013/03/24/bouncy-castle-subject-alternative-names/#use-a-subject-alternative-name-extension) allow the client's certificate to describe which DNS host it was looking for.

### Configuring the DNS Names in the Subject Alternative Names During Certificate Creation

The domain name of your server can be added to the Subject Alternative Names section of the WebID Certificates if you specify it on the `WebIdX509CertificateBuilderFactory`:

```java
    import com.ironhorsesoftware.jsse.webid.certs.WebIdX509CertificateBuilderFactory;

    final WebIdX509CertificateBuilderFactory factory = ...;
    factory.addServerDnsName("www.example.com");
```

### Configuring the WebIdSSLEngineBuilder

The following code will create an `SSLEngine` ready for use.  You need to set up the `KeyStore`s for the key manager and trust manager.

```java
    import javax.net.ssl.KeyStoreBuilderParameters;
    import javax.net.ssl.SSLEngine;

    import com.ironhorsesoftware.jsse.webid.WebIdSSLEngineBuilder;


    final KeyStoreBuilderParameters keyManagerFactoryParams = ...;   // Configures the KeyStore used by the KeyManager for PKIX certificate validation.
    final KeyStoreBuilderParameters trustManagerFactoryParams = ...; // Configures the KeyStore used by the WebIdTrustManager WebID certificate validation.

    final WebIdSSLEngineBuilder builder = new WebIdSSLEngineBuilder();
    builder.setPkixKeyManagerFactoryParams(keyManagerFactoryParams);
    builder.setWebIdTrustManagerFactoryParams(trustManagerFactoryParams);

    // -- OPTIONAL PARAMETERS -- //

    // If the server certificate chain to present cannot be resolved by either SNI or the client certificate, use the one for this alias instead.
    builder.setDefaultAlias("www.example.com");

    // The default behavior is to only ask the client for certificates with an issuer of CN=WebID,O={}.
    // Setting this field to false will allow any client-side certificate to be sent along.
    builder.setRequireWebIdIssuedCertificates(false);

    // -- END OF OPTIONAL PARAMETERS -- //

    // This SSLEngine, in addition to the above configuration, will ask for
    // client certificates in WANT mode, and use the server's preference for
    // the cipher suite order (and not the client's).
    final SSLEngine engine = builder.build();
```
