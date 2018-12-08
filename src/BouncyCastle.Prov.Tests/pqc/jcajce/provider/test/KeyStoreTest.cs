using org.bouncycastle.asn1.bc;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using TestCase = junit.framework.TestCase;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using BCObjectIdentifiers = org.bouncycastle.asn1.bc.BCObjectIdentifiers;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using X500NameBuilder = org.bouncycastle.asn1.x500.X500NameBuilder;
	using BCStyle = org.bouncycastle.asn1.x500.style.BCStyle;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using TBSCertificate = org.bouncycastle.asn1.x509.TBSCertificate;
	using Time = org.bouncycastle.asn1.x509.Time;
	using V3TBSCertificateGenerator = org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using McElieceKeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;
	using SPHINCS256KeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
	using XMSSMTParameterSpec = org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;

	public class KeyStoreTest : TestCase
	{
		private const long ONE_DAY_IN_MILLIS = 24 * 60 * 60 * 1000;
		private static readonly long TEN_YEARS_IN_MILLIS = 10l * 365 * ONE_DAY_IN_MILLIS;

		private static Map algIds = new HashMap();

		static KeyStoreTest()
		{
			algIds.put("SHA512WITHSPHINCS256", new AlgorithmIdentifier(BCObjectIdentifiers_Fields.sphincs256_with_SHA512));
			algIds.put("SHA256WITHXMSSMT", new AlgorithmIdentifier(BCObjectIdentifiers_Fields.xmss_mt_SHA256ph));
			algIds.put("SHA512WITHXMSSMT", new AlgorithmIdentifier(BCObjectIdentifiers_Fields.xmss_mt_SHA512ph));
		}

		public virtual void setUp()
		{
			Security.addProvider(new BouncyCastleProvider());
			Security.addProvider(new BouncyCastlePQCProvider());
		}

		public virtual void testPKCS12()
		{
			tryKeyStore("PKCS12");
			tryKeyStore("PKCS12-DEF");
		}

		public virtual void testBKS()
		{
			tryKeyStore("BKS");
			tryKeyStore("UBER");
		}

		public virtual void testBCFKS()
		{
			tryKeyStore("BCFKS-DEF");
		}

		private void tryKeyStore(string format)
		{
			// Keystore to store certificates and private keys
			KeyStore store = KeyStore.getInstance(format, "BC");

			store.load(null, null);

			string password = "qwertz";
			// XMSS
			X500NameBuilder nameBuilder = new X500NameBuilder();

			nameBuilder.addRDN(BCStyle.CN, "Root CA");

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

			kpg.initialize(new XMSSMTParameterSpec(20, 10, XMSSMTParameterSpec.SHA256), new SecureRandom());

			KeyPair kp = kpg.generateKeyPair();
			// root CA
			X509Certificate rootCA = createPQSelfSignedCert(nameBuilder.build(), "SHA256WITHXMSSMT", kp);
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = rootCA;
			// store root private key
			string alias1 = "xmssmt private";
			store.setKeyEntry(alias1, kp.getPrivate(), password.ToCharArray(), chain);
			// store root certificate
			store.setCertificateEntry("root ca", rootCA);

			// McEliece
			kpg = KeyPairGenerator.getInstance("McEliece", "BCPQC");

			McElieceKeyGenParameterSpec @params = new McElieceKeyGenParameterSpec(9, 33);
			kpg.initialize(@params);

			KeyPair mcelieceKp = kpg.generateKeyPair();

			ExtensionsGenerator extGenerator = new ExtensionsGenerator();
			extGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
			extGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.encipherOnly));

			X509Certificate cert1 = createCert(nameBuilder.build(), kp.getPrivate(), new X500Name("CN=meceliece"), "SHA256WITHXMSSMT", extGenerator.generate(), mcelieceKp.getPublic());

			X509Certificate[] chain1 = new X509Certificate[2];
			chain1[1] = rootCA;
			chain1[0] = cert1;

			// SPHINCS-256
			kpg = KeyPairGenerator.getInstance("SPHINCS256", "BCPQC");

			kpg.initialize(new SPHINCS256KeyGenParameterSpec(SPHINCS256KeyGenParameterSpec.SHA512_256));

			KeyPair sphincsKp = kpg.generateKeyPair();

			extGenerator = new ExtensionsGenerator();
			extGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
			extGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

			X509Certificate cert2 = createCert(nameBuilder.build(), sphincsKp.getPrivate(), new X500Name("CN=sphincs256"), "SHA512WITHSPHINCS256", extGenerator.generate(), sphincsKp.getPublic());

			X509Certificate[] chain2 = new X509Certificate[2];
			chain2[1] = rootCA;
			chain2[0] = cert2;

			string alias2 = "private key 1";
			string alias3 = "private key 2";

			// store private keys
			store.setKeyEntry(alias2, mcelieceKp.getPrivate(), password.ToCharArray(), chain1);
			store.setKeyEntry(alias3, sphincsKp.getPrivate(), password.ToCharArray(), chain2);

			// store certificates
			store.setCertificateEntry("cert 1", cert1);
			store.setCertificateEntry("cert 2", cert2);

			// can't restore keys from keystore
			Key k1 = store.getKey(alias1, password.ToCharArray());

			assertEquals(kp.getPrivate(), k1);

			Key k2 = store.getKey(alias2, password.ToCharArray());

			assertEquals(mcelieceKp.getPrivate(), k2);

			Key k3 = store.getKey(alias3, password.ToCharArray());

			assertEquals(sphincsKp.getPrivate(), k3);

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store.store(bOut, "fred".ToCharArray());

			KeyStore bcStore = KeyStore.getInstance(format, "BC");

			bcStore.load(new ByteArrayInputStream(bOut.toByteArray()), "fred".ToCharArray());

			k1 = store.getKey(alias1, password.ToCharArray());

			assertEquals(kp.getPrivate(), k1);

			k2 = store.getKey(alias2, password.ToCharArray());

			assertEquals(mcelieceKp.getPrivate(), k2);

			k3 = store.getKey(alias3, password.ToCharArray());

			assertEquals(sphincsKp.getPrivate(), k3);
		}

		private static X509Certificate createPQSelfSignedCert(X500Name dn, string sigName, KeyPair keyPair)
		{
			V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
			long time = System.currentTimeMillis();
			AtomicLong serialNumber = new AtomicLong(System.currentTimeMillis());
			certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
			certGen.setIssuer(dn);
			certGen.setSubject(dn);
			certGen.setStartDate(new Time(new DateTime(time - 5000)));
			certGen.setEndDate(new Time(new DateTime(time + TEN_YEARS_IN_MILLIS)));
			certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
			certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

			ExtensionsGenerator extGenerator = new ExtensionsGenerator();
			extGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
			extGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));

			certGen.setExtensions(extGenerator.generate());

			Signature sig = Signature.getInstance(sigName, BouncyCastlePQCProvider.PROVIDER_NAME);

			sig.initSign(keyPair.getPrivate());

			sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding_Fields.DER));

			TBSCertificate tbsCert = certGen.generateTBSCertificate();

			ASN1EncodableVector v = new ASN1EncodableVector();
			// TBS
			v.add(tbsCert);
			// Algorithm Identifier
			v.add((AlgorithmIdentifier)algIds.get(sigName));
			// Signature
			v.add(new DERBitString(sig.sign()));

			return (X509Certificate)CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME).generateCertificate(new ByteArrayInputStream((new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER)));
		}

		private static X509Certificate createCert(X500Name signerName, PrivateKey signerKey, X500Name dn, string sigName, Extensions extensions, PublicKey pubKey)
		{
			V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

			long time = System.currentTimeMillis();
			AtomicLong serialNumber = new AtomicLong(System.currentTimeMillis());

			certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
			certGen.setIssuer(signerName);
			certGen.setSubject(dn);
			certGen.setStartDate(new Time(new DateTime(time - 5000)));
			certGen.setEndDate(new Time(new DateTime(time + TEN_YEARS_IN_MILLIS)));
			certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
			certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));

			certGen.setExtensions(extensions);

			Signature sig = Signature.getInstance(sigName, BouncyCastlePQCProvider.PROVIDER_NAME);

			sig.initSign(signerKey);

			sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding_Fields.DER));

			TBSCertificate tbsCert = certGen.generateTBSCertificate();

			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(tbsCert);
			v.add((AlgorithmIdentifier)algIds.get(sigName));
			v.add(new DERBitString(sig.sign()));

			return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream((new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER)));
		}
	}

}