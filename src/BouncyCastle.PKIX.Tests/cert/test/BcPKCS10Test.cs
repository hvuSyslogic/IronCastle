using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.cert.test
{

	using TestCase = junit.framework.TestCase;
	using Attribute = org.bouncycastle.asn1.pkcs.Attribute;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using X500NameBuilder = org.bouncycastle.asn1.x500.X500NameBuilder;
	using RFC4519Style = org.bouncycastle.asn1.x500.style.RFC4519Style;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using BcX509ExtensionUtils = org.bouncycastle.cert.bc.BcX509ExtensionUtils;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using AsymmetricCipherKeyPairGenerator = org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
	using RSAKeyPairGenerator = org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using RSAKeyGenerationParameters = org.bouncycastle.crypto.@params.RSAKeyGenerationParameters;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using DefaultDigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DefaultDigestAlgorithmIdentifierFinder;
	using DefaultSignatureAlgorithmIdentifierFinder = org.bouncycastle.@operator.DefaultSignatureAlgorithmIdentifierFinder;
	using BcContentSignerBuilder = org.bouncycastle.@operator.bc.BcContentSignerBuilder;
	using BcRSAContentSignerBuilder = org.bouncycastle.@operator.bc.BcRSAContentSignerBuilder;
	using BcRSAContentVerifierProviderBuilder = org.bouncycastle.@operator.bc.BcRSAContentVerifierProviderBuilder;
	using PKCS10CertificationRequest = org.bouncycastle.pkcs.PKCS10CertificationRequest;
	using PKCS10CertificationRequestBuilder = org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
	using BcPKCS10CertificationRequest = org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequest;
	using BcPKCS10CertificationRequestBuilder = org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequestBuilder;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BcPKCS10Test : TestCase
	{
		public virtual string getName()
		{
			return "PKCS10CertRequest";
		}

		private void generationTest(int keySize, string keyName, string sigName)
		{
			AsymmetricCipherKeyPairGenerator kpg = new RSAKeyPairGenerator();
			RSAKeyGenerationParameters genParam = new RSAKeyGenerationParameters(BigInteger.valueOf(0x1001), new SecureRandom(), keySize, 25);

			kpg.init(genParam);

			AsymmetricCipherKeyPair kp = kpg.generateKeyPair();


			X500NameBuilder x500NameBld = new X500NameBuilder(RFC4519Style.INSTANCE);

			x500NameBld.addRDN(RFC4519Style.c, "AU");
			x500NameBld.addRDN(RFC4519Style.o, "The Legion of the Bouncy Castle");
			x500NameBld.addRDN(RFC4519Style.l, "Melbourne");
			x500NameBld.addRDN(RFC4519Style.st, "Victoria");
			x500NameBld.addRDN(PKCSObjectIdentifiers_Fields.pkcs_9_at_emailAddress, "feedback-crypto@bouncycastle.org");

			X500Name subject = x500NameBld.build();

			PKCS10CertificationRequestBuilder requestBuilder = new BcPKCS10CertificationRequestBuilder(subject, kp.getPublic());

			DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
			DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();

			AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA1withRSA");

			AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);

			BcContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

			PKCS10CertificationRequest req1 = requestBuilder.build(contentSignerBuilder.build(kp.getPrivate()));

			BcPKCS10CertificationRequest req2 = new BcPKCS10CertificationRequest(req1.getEncoded());

			if (!req2.isSignatureValid((new BcRSAContentVerifierProviderBuilder(digAlgFinder)).build(kp.getPublic())))
			{
				fail(sigName + ": Failed verify check.");
			}

			if (!Arrays.areEqual(req2.getSubjectPublicKeyInfo().getEncoded(), req1.getSubjectPublicKeyInfo().getEncoded()))
			{
				fail(keyName + ": Failed public key check.");
			}
		}

		private void createPSSTest(string algorithm)
		{
			AsymmetricKeyParameter pubKey = new RSAKeyParameters(false, new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",16), new BigInteger("010001",16));

			AsymmetricKeyParameter privKey = new RSAPrivateCrtKeyParameters(new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",16), new BigInteger("010001",16), new BigInteger("33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325",16), new BigInteger("e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443",16), new BigInteger("b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd",16), new BigInteger("28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979",16), new BigInteger("1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729",16), new BigInteger("27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d",16));

			DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
			DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();

			AlgorithmIdentifier sigAlgId = sigAlgFinder.find(algorithm);
			AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
			BcContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

			PKCS10CertificationRequest req = (new BcPKCS10CertificationRequestBuilder(new X500Name("CN=XXX"), pubKey)).build(contentSignerBuilder.build(privKey));
			if (!req.isSignatureValid((new BcRSAContentVerifierProviderBuilder(digAlgFinder)).build(pubKey)))
			{
				fail("Failed verify check PSS.");
			}

			BcPKCS10CertificationRequest bcReq = new BcPKCS10CertificationRequest(req.getEncoded());
			if (!bcReq.isSignatureValid((new BcRSAContentVerifierProviderBuilder(digAlgFinder)).build(bcReq.getPublicKey())))
			{
				fail("Failed verify check PSS encoded.");
			}

			if (!bcReq.getSignatureAlgorithm().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS))
			{
				fail("PSS oid incorrect.");
			}

			if (bcReq.getSignatureAlgorithm().getParameters() == null)
			{
				fail("PSS parameters incorrect.");
			}
		}

		 // previous code found to cause a NullPointerException
		private void nullPointerTest()
		{
			AsymmetricCipherKeyPairGenerator kpg = new RSAKeyPairGenerator();
			RSAKeyGenerationParameters genParam = new RSAKeyGenerationParameters(BigInteger.valueOf(0x1001), new SecureRandom(), 1024, 25);

			kpg.init(genParam);

			AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
			ExtensionsGenerator extGen = new ExtensionsGenerator();

			extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
			extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

			BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils(new SHA1DigestCalculator());

			SubjectKeyIdentifier subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(kp.getPublic());

			extGen.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

			DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
			DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();

			AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA1withRSA");

			AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);

			BcContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

			PKCS10CertificationRequest p1 = (new BcPKCS10CertificationRequestBuilder(new X500Name("cn=csr"), kp.getPublic())).addAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_extensionRequest, extGen.generate()).build(contentSignerBuilder.build(kp.getPrivate()));
			PKCS10CertificationRequest p2 = (new BcPKCS10CertificationRequestBuilder(new X500Name("cn=csr"), kp.getPublic())).addAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_extensionRequest, extGen.generate()).build(contentSignerBuilder.build(kp.getPrivate()));

			if (!p1.Equals(p2))
			{
				fail("cert request comparison failed");
			}

			Attribute[] attr1 = p1.getAttributes();
			Attribute[] attr2 = p1.getAttributes();

			checkAttrs(1, attr1, attr2);

			attr1 = p1.getAttributes(PKCSObjectIdentifiers_Fields.pkcs_9_at_extensionRequest);
			attr2 = p1.getAttributes(PKCSObjectIdentifiers_Fields.pkcs_9_at_extensionRequest);

			checkAttrs(1, attr1, attr2);
		}

		private void checkAttrs(int expectedLength, Attribute[] attr1, Attribute[] attr2)
		{
			if (expectedLength != attr1.Length)
			{
				fail("expected length mismatch");
			}

			if (attr1.Length != attr2.Length)
			{
				fail("atrribute length mismatch");
			}

			for (int i = 0; i != attr1.Length; i++)
			{
				if (!attr1[i].Equals(attr2[i]))
				{
					fail("atrribute mismatch");
				}
			}
		}

		public virtual void testPKCS10()
		{
			generationTest(512, "RSA", "SHA1withRSA");

			createPSSTest("SHA1withRSAandMGF1");
			createPSSTest("SHA224withRSAandMGF1");
			createPSSTest("SHA256withRSAandMGF1");
			createPSSTest("SHA384withRSAandMGF1");

			nullPointerTest();
		}
	}

}