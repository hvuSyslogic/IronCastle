using org.bouncycastle.asn1.edec;

using System;

namespace org.bouncycastle.jce.provider.test
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using DHUParameterSpec = org.bouncycastle.jcajce.spec.DHUParameterSpec;
	using EdDSAParameterSpec = org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
	using UserKeyingMaterialSpec = org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
	using XDHParameterSpec = org.bouncycastle.jcajce.spec.XDHParameterSpec;
	using Strings = org.bouncycastle.util.Strings;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class EdECTest : SimpleTest
	{
		private static readonly byte[] pubEnc = Base64.decode("MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=");

		private static readonly byte[] privEnc = Base64.decode("MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC");

		private static readonly byte[] privWithPubEnc = Base64.decode("MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC" + "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB" + "Z9w7lshQhqowtrbLDFw4rXAxZuE=");

		public static readonly byte[] x25519Cert = Base64.decode("MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZX" + "N0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQD" + "DA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJj" + "ga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAg" + "BgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v" + "/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cg" + "w1AH9efZBw==");

		public override string getName()
		{
			return "EdEC";
		}

		public override void performTest()
		{
			KeyFactory kFact = KeyFactory.getInstance("EdDSA", "BC");

			PublicKey pub = kFact.generatePublic(new X509EncodedKeySpec(pubEnc));

			isTrue("pub failed", areEqual(pubEnc, pub.getEncoded()));

			serializationTest("ref pub", pub);

			PrivateKey priv = kFact.generatePrivate(new PKCS8EncodedKeySpec(privEnc));

			isTrue("priv failed", areEqual(privEnc, priv.getEncoded()));

			priv = kFact.generatePrivate(new PKCS8EncodedKeySpec(privWithPubEnc));

			isTrue("priv with pub failed", areEqual(privWithPubEnc, priv.getEncoded()));

			serializationTest("ref priv", priv);

			Signature sig = Signature.getInstance("EDDSA", "BC");

			Certificate x25519Cert = Certificate.getInstance(EdECTest.x25519Cert);

			sig.initVerify(pub);

			sig.update(x25519Cert.getTBSCertificate().getEncoded());

			isTrue(sig.verify(x25519Cert.getSignature().getBytes()));

			x448AgreementTest();
			x25519AgreementTest();
			ed448SignatureTest();
			ed25519SignatureTest();
			x448withCKDFTest();
			x25519withCKDFTest();
			x448withKDFTest();
			x25519withKDFTest();
			x448UwithKDFTest();
			x25519UwithKDFTest();

			xdhGeneratorTest();
			eddsaGeneratorTest();

			keyTest("X448");
			keyTest("X25519");
			keyTest("Ed448");
			keyTest("Ed25519");

			keyFactoryTest("X448", EdECObjectIdentifiers_Fields.id_X448);
			keyFactoryTest("X25519", EdECObjectIdentifiers_Fields.id_X25519);
			keyFactoryTest("Ed448", EdECObjectIdentifiers_Fields.id_Ed448);
			keyFactoryTest("Ed25519", EdECObjectIdentifiers_Fields.id_Ed25519);
		}

		private void keyFactoryTest(string algorithm, ASN1ObjectIdentifier algOid)
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");
			KeyFactory kFact = KeyFactory.getInstance((algorithm.StartsWith("X", StringComparison.Ordinal) ? "XDH" : "EdDSA"), "BC");

			KeyPair kp = kpGen.generateKeyPair();

			Set<string> alts = new HashSet<string>();

			alts.add("X448");
			alts.add("X25519");
			alts.add("Ed448");
			alts.add("Ed25519");

			alts.remove(algorithm);

			PrivateKey k1 = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

			checkEquals(algorithm, kp.getPrivate(), k1);

			PublicKey k2 = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

			checkEquals(algorithm, kp.getPublic(), k2);

			for (Iterator<string> it = alts.iterator(); it.hasNext();)
			{
				string altAlg = (string)it.next();

				kFact = KeyFactory.getInstance(altAlg, "BC");

				try
				{
					k1 = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
					fail("no exception");
				}
				catch (InvalidKeySpecException e)
				{
					isEquals("encoded key spec not recognized: algorithm identifier " + algOid.getId() + " in key not recognized", e.Message);
				}

				try
				{
					k2 = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
					fail("no exception");
				}
				catch (InvalidKeySpecException e)
				{
					isEquals("encoded key spec not recognized: algorithm identifier " + algOid.getId() + " in key not recognized", e.Message);
				}
			}
		}

		private void keyTest(string algorithm)
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");

			KeyFactory kFact = KeyFactory.getInstance(algorithm, "BC");

			KeyPair kp = kpGen.generateKeyPair();

			PrivateKey k1 = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

			checkEquals(algorithm, kp.getPrivate(), k1);

			PublicKey k2 = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

			checkEquals(algorithm, kp.getPublic(), k2);

			serializationTest(algorithm, kp.getPublic());
			serializationTest(algorithm, kp.getPrivate());

			string pubString = kp.getPublic().ToString();
			string privString = kp.getPrivate().ToString();

			isTrue(pubString.StartsWith(algorithm + " Public Key [", StringComparison.Ordinal));
			isTrue(privString.StartsWith(algorithm + " Private Key [", StringComparison.Ordinal));
			isTrue(privString.Substring((algorithm + " Private Key [").Length).Equals(pubString.Substring((algorithm + " Public Key [").Length)));
		}

		private void xdhGeneratorTest()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("XDH", "BC");

			kpGen.initialize(new XDHParameterSpec(XDHParameterSpec.X448));

			KeyPair kp = kpGen.generateKeyPair();

			isTrue("X448".Equals(kp.getPublic().getAlgorithm()));

			kpGen.initialize(new ECGenParameterSpec(XDHParameterSpec.X448));

			kp = kpGen.generateKeyPair();

			isTrue("X448".Equals(kp.getPublic().getAlgorithm()));

			kpGen.initialize(448);

			kp = kpGen.generateKeyPair();

			isTrue("X448".Equals(kp.getPublic().getAlgorithm()));

			kpGen = KeyPairGenerator.getInstance("XDH", "BC");

			kpGen.initialize(new XDHParameterSpec(XDHParameterSpec.X25519));

			kp = kpGen.generateKeyPair();

			isTrue("X25519".Equals(kp.getPublic().getAlgorithm()));

			kpGen.initialize(new ECGenParameterSpec(XDHParameterSpec.X25519));

			kp = kpGen.generateKeyPair();

			isTrue("X25519".Equals(kp.getPublic().getAlgorithm()));

			kpGen.initialize(256);

			kp = kpGen.generateKeyPair();

			isTrue("X25519".Equals(kp.getPublic().getAlgorithm()));

			kpGen.initialize(255);

			kp = kpGen.generateKeyPair();

			isTrue("X25519".Equals(kp.getPublic().getAlgorithm()));

			kpGen = KeyPairGenerator.getInstance("XDH", "BC");

			try
			{
				kpGen.generateKeyPair();
				fail("no exception");
			}
			catch (IllegalStateException e)
			{
				isEquals("generator not correctly initialized", e.getMessage());
			}

			try
			{
				kpGen.initialize(new EdDSAParameterSpec(EdDSAParameterSpec.Ed448));
				fail("no exception");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				isEquals("parameterSpec for wrong curve type", e.getMessage());
			}

			try
			{
				kpGen.initialize(1024);
				fail("no exception");
			}
			catch (InvalidParameterException e)
			{
				isEquals("unknown key size", e.getMessage());
			}

			try
			{
				kpGen.initialize(new EdDSAParameterSpec(EdDSAParameterSpec.Ed448));
				fail("no exception");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				isEquals("parameterSpec for wrong curve type", e.getMessage());
			}

			try
			{
				new XDHParameterSpec(EdDSAParameterSpec.Ed448);
			}
			catch (IllegalArgumentException e)
			{
				isEquals("unrecognized curve name: Ed448", e.getMessage());
			}
		}

		private void eddsaGeneratorTest()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EdDSA", "BC");

			kpGen.initialize(new EdDSAParameterSpec(EdDSAParameterSpec.Ed448));

			KeyPair kp = kpGen.generateKeyPair();

			isTrue("Ed448".Equals(kp.getPublic().getAlgorithm()));

			kpGen.initialize(new EdDSAParameterSpec(EdDSAParameterSpec.Ed448));

			kp = kpGen.generateKeyPair();

			isTrue("Ed448".Equals(kp.getPublic().getAlgorithm()));

			kpGen.initialize(448);

			kp = kpGen.generateKeyPair();

			isTrue("Ed448".Equals(kp.getPublic().getAlgorithm()));

			kpGen = KeyPairGenerator.getInstance("EdDSA", "BC");

			kpGen.initialize(new EdDSAParameterSpec(EdDSAParameterSpec.Ed25519));

			kp = kpGen.generateKeyPair();

			isTrue("Ed25519".Equals(kp.getPublic().getAlgorithm()));

			kpGen.initialize(new ECGenParameterSpec(EdDSAParameterSpec.Ed25519));

			kp = kpGen.generateKeyPair();

			isTrue("Ed25519".Equals(kp.getPublic().getAlgorithm()));

			kpGen.initialize(256);

			kp = kpGen.generateKeyPair();

			isTrue("Ed25519".Equals(kp.getPublic().getAlgorithm()));

			kpGen.initialize(255);

			kp = kpGen.generateKeyPair();

			isTrue("Ed25519".Equals(kp.getPublic().getAlgorithm()));

			kpGen = KeyPairGenerator.getInstance("EdDSA", "BC");

			try
			{
				kpGen.generateKeyPair();
				fail("no exception");
			}
			catch (IllegalStateException e)
			{
				isEquals("generator not correctly initialized", e.getMessage());
			}

			try
			{
				kpGen.initialize(new XDHParameterSpec(XDHParameterSpec.X448));
				fail("no exception");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				isEquals("parameterSpec for wrong curve type", e.getMessage());
			}

			try
			{
				kpGen.initialize(new XDHParameterSpec(XDHParameterSpec.X25519));
				fail("no exception");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				isEquals("parameterSpec for wrong curve type", e.getMessage());
			}

			try
			{
				kpGen.initialize(1024);
				fail("no exception");
			}
			catch (InvalidParameterException e)
			{
				isEquals("unknown key size", e.getMessage());
			}

			try
			{
				new EdDSAParameterSpec(XDHParameterSpec.X448);
			}
			catch (IllegalArgumentException e)
			{
				isEquals("unrecognized curve name: X448", e.getMessage());
			}
		}

		private void checkEquals(string algorithm, Key ka, Key kb)
		{
			isEquals(algorithm + " check equals", ka, kb);
			isEquals(algorithm + " check hashCode", ka.GetHashCode(), kb.GetHashCode());
		}

		private void serializationTest(string algorithm, Key key)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ObjectOutputStream oOut = new ObjectOutputStream(bOut);

			oOut.writeObject(key);
			oOut.close();

			ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

			Key rk = (Key)oIn.readObject();

			checkEquals(algorithm, key, rk);
		}

		private void x448AgreementTest()
		{
			agreementTest("X448");
		}

		private void x25519AgreementTest()
		{
			agreementTest("X25519");
		}

		private void x448withCKDFTest()
		{
			agreementTest("X448withSHA512CKDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
		}

		private void x25519withCKDFTest()
		{
			agreementTest("X25519withSHA256CKDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
		}

		private void x448withKDFTest()
		{
			agreementTest("X448withSHA512KDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
		}

		private void x25519withKDFTest()
		{
			agreementTest("X25519withSHA256KDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
		}

		private void ed448SignatureTest()
		{
			signatureTest("Ed448");
		}

		private void ed25519SignatureTest()
		{
			signatureTest("Ed25519");
		}

		private void agreementTest(string algorithm)
		{
			agreementTest(algorithm, null);
		}

		private void agreementTest(string algorithm, AlgorithmParameterSpec spec)
		{
			KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm, "BC");

			KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm.StartsWith("X448", StringComparison.Ordinal) ? "X448" : "X25519", "BC");

			KeyPair kp1 = kpGen.generateKeyPair();
			KeyPair kp2 = kpGen.generateKeyPair();

			keyAgreement.init(kp1.getPrivate());

			keyAgreement.doPhase(kp2.getPublic(), true);

			byte[] sec1 = keyAgreement.generateSecret();

			keyAgreement.init(kp2.getPrivate());

			keyAgreement.doPhase(kp1.getPublic(), true);

			byte[] sec2 = keyAgreement.generateSecret();

			isTrue(areEqual(sec1, sec2));

			if (spec != null)
			{
				keyAgreement.init(kp1.getPrivate(), spec);

				keyAgreement.doPhase(kp2.getPublic(), true);

				byte[] sec3 = keyAgreement.generateSecret();

				keyAgreement.init(kp2.getPrivate(), spec);

				keyAgreement.doPhase(kp1.getPublic(), true);

				byte[] sec4 = keyAgreement.generateSecret();

				isTrue(areEqual(sec3, sec4));
				isTrue(!areEqual(sec1, sec4));
			}
		}

		private void x448UwithKDFTest()
		{
			unifiedAgreementTest("X448UwithSHA512KDF");
		}

		private void x25519UwithKDFTest()
		{
			unifiedAgreementTest("X25519UwithSHA256KDF");
		}

		private void unifiedAgreementTest(string algorithm)
		{
			KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm, "BC");

			KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm.StartsWith("X448", StringComparison.Ordinal) ? "X448" : "X25519", "BC");

			KeyPair aKp1 = kpGen.generateKeyPair();
			KeyPair aKp2 = kpGen.generateKeyPair();

			KeyPair bKp1 = kpGen.generateKeyPair();
			KeyPair bKp2 = kpGen.generateKeyPair();

			keyAgreement.init(aKp1.getPrivate(), new DHUParameterSpec(aKp2, bKp2.getPublic(), Hex.decode("beeffeed")));

			keyAgreement.doPhase(bKp1.getPublic(), true);

			byte[] sec1 = keyAgreement.generateSecret();

			keyAgreement.init(bKp1.getPrivate(), new DHUParameterSpec(aKp2, bKp2.getPublic(), Hex.decode("beeffeed")));

			keyAgreement.doPhase(aKp1.getPublic(), true);

			byte[] sec2 = keyAgreement.generateSecret();

			isTrue(areEqual(sec1, sec2));

			keyAgreement.init(bKp1.getPrivate(), new DHUParameterSpec(aKp2, bKp2.getPublic(), Hex.decode("feed")));

			keyAgreement.doPhase(aKp1.getPublic(), true);

			byte[] sec3 = keyAgreement.generateSecret();

			isTrue(!areEqual(sec1, sec3));
		}

		private void signatureTest(string algorithm)
		{
			byte[] msg = Strings.toByteArray("Hello, world!");
			Signature signature = Signature.getInstance(algorithm, "BC");

			KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");

			KeyPair kp = kpGen.generateKeyPair();

			signature.initSign(kp.getPrivate());

			signature.update(msg);

			byte[] sig = signature.sign();

			signature.initVerify(kp.getPublic());

			signature.update(msg);

			isTrue(signature.verify(sig));

			// try with random - should be ignored

			signature.initSign(kp.getPrivate(), new SecureRandom());

			signature.update(msg);

			sig = signature.sign();

			signature.initVerify(kp.getPublic());

			signature.update(msg);

			isTrue(signature.verify(sig));
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new EdECTest());
		}
	}

}