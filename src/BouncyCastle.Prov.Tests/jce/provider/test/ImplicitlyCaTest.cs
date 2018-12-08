using org.bouncycastle.jcajce.provider.config;

namespace org.bouncycastle.jce.provider.test
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using ECPrivateKey = org.bouncycastle.jce.interfaces.ECPrivateKey;
	using ECPublicKey = org.bouncycastle.jce.interfaces.ECPublicKey;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using ECPrivateKeySpec = org.bouncycastle.jce.spec.ECPrivateKeySpec;
	using ECPublicKeySpec = org.bouncycastle.jce.spec.ECPublicKeySpec;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using FixedSecureRandom = org.bouncycastle.util.test.FixedSecureRandom;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class ImplicitlyCaTest : SimpleTest
	{
		private bool InstanceFieldsInitialized = false;

		public ImplicitlyCaTest()
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
		}

		private void InitializeInstanceFields()
		{
			random = new FixedSecureRandom(new FixedSecureRandom.Source[]
			{
				new FixedSecureRandom.Data(k1),
				new FixedSecureRandom.Data(k2)
			});
		}

		internal byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
		internal byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

		internal SecureRandom random;

		public override void performTest()
		{
			testBCAPI();

			testJDKAPI();

			testKeyFactory();

			testBasicThreadLocal();
		}

		private void testBCAPI()
		{
			KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

			X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
			ECParameterSpec ecSpec = new ECParameterSpec(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());

			ConfigurableProvider config = (ConfigurableProvider)Security.getProvider("BC");

			config.setParameter(ConfigurableProvider_Fields.EC_IMPLICITLY_CA, ecSpec);

			g.initialize(null, new SecureRandom());

			KeyPair p = g.generateKeyPair();

			ECPrivateKey sKey = (ECPrivateKey)p.getPrivate();
			ECPublicKey vKey = (ECPublicKey)p.getPublic();

			testECDSA(sKey, vKey);

			testBCParamsAndQ(sKey, vKey);
			testEC5Params(sKey, vKey);

			testEncoding(sKey, vKey);
		}

		private void testKeyFactory()
		{
			KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

			X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
			ECParameterSpec ecSpec = new ECParameterSpec(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());

			ConfigurableProvider config = (ConfigurableProvider)Security.getProvider("BC");

			config.setParameter(ConfigurableProvider_Fields.EC_IMPLICITLY_CA, ecSpec);

			g.initialize(null, new SecureRandom());

			KeyPair p = g.generateKeyPair();

			ECPrivateKey sKey = (ECPrivateKey)p.getPrivate();
			ECPublicKey vKey = (ECPublicKey)p.getPublic();

			KeyFactory fact = KeyFactory.getInstance("ECDSA", "BC");

			vKey = (ECPublicKey)fact.generatePublic(new ECPublicKeySpec(vKey.getQ(), null));
			sKey = (ECPrivateKey)fact.generatePrivate(new ECPrivateKeySpec(sKey.getD(), null));

			testECDSA(sKey, vKey);

			testBCParamsAndQ(sKey, vKey);
			testEC5Params(sKey, vKey);

			testEncoding(sKey, vKey);

			ECPublicKey vKey2 = (ECPublicKey)fact.generatePublic(new ECPublicKeySpec(vKey.getQ(), null));
			ECPrivateKey sKey2 = (ECPrivateKey)fact.generatePrivate(new ECPrivateKeySpec(sKey.getD(), null));

			if (!vKey.Equals(vKey2) || vKey.GetHashCode() != vKey2.GetHashCode())
			{
				fail("public equals/hashCode failed");
			}

			if (!sKey.Equals(sKey2) || sKey.GetHashCode() != sKey2.GetHashCode())
			{
				fail("private equals/hashCode failed");
			}

			// check we can get specs.
			fact.getKeySpec(vKey, typeof(java.security.spec.ECPublicKeySpec));

			fact.getKeySpec(sKey, typeof(java.security.spec.ECPrivateKeySpec));
		}

		private void testJDKAPI()
		{
			KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

			EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

			java.security.spec.ECParameterSpec ecSpec = new java.security.spec.ECParameterSpec(curve, ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), 1); // h


			ConfigurableProvider config = (ConfigurableProvider)Security.getProvider("BC");

			config.setParameter(ConfigurableProvider_Fields.EC_IMPLICITLY_CA, ecSpec);

			g.initialize(null, new SecureRandom());

			KeyPair p = g.generateKeyPair();

			ECPrivateKey sKey = (ECPrivateKey)p.getPrivate();
			ECPublicKey vKey = (ECPublicKey)p.getPublic();

			testECDSA(sKey, vKey);

			testBCParamsAndQ(sKey, vKey);
			testEC5Params(sKey, vKey);

			testEncoding(sKey, vKey);
		}

		private void testBasicThreadLocal()
		{
			KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

			EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

			java.security.spec.ECParameterSpec ecSpec = new java.security.spec.ECParameterSpec(curve, ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), 1); // h


			ConfigurableProvider config = (ConfigurableProvider)Security.getProvider("BC");

			config.setParameter(ConfigurableProvider_Fields.THREAD_LOCAL_EC_IMPLICITLY_CA, ecSpec);

			g.initialize(null, new SecureRandom());

			KeyPair p = g.generateKeyPair();

			ECPrivateKey sKey = (ECPrivateKey)p.getPrivate();
			ECPublicKey vKey = (ECPublicKey)p.getPublic();

			testECDSA(sKey, vKey);

			testBCParamsAndQ(sKey, vKey);
			testEC5Params(sKey, vKey);

			testEncoding(sKey, vKey);
		}

		private void testECDSA(ECPrivateKey sKey, ECPublicKey vKey)
		{
			byte[] data = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
			Signature s = Signature.getInstance("ECDSA", "BC");

			s.initSign(sKey);

			s.update(data);

			byte[] sigBytes = s.sign();

			s = Signature.getInstance("ECDSA", "BC");

			s.initVerify(vKey);

			s.update(data);

			if (!s.verify(sigBytes))
			{
				fail("ECDSA verification failed");
			}
		}

		private void testEncoding(ECPrivateKey privKey, ECPublicKey pubKey)
		{
			KeyFactory kFact = KeyFactory.getInstance("ECDSA", "BC");

			byte[] bytes = privKey.getEncoded();

			PrivateKeyInfo sInfo = PrivateKeyInfo.getInstance((new ASN1InputStream(bytes)).readObject());

			if (!sInfo.getPrivateKeyAlgorithm().getParameters().Equals(DERNull.INSTANCE))
			{
				fail("private key parameters wrong");
			}

			ECPrivateKey sKey = (ECPrivateKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(bytes));

			if (!sKey.Equals(privKey))
			{
				fail("private equals failed");
			}

			if (sKey.GetHashCode() != privKey.GetHashCode())
			{
				fail("private hashCode failed");
			}

			bytes = pubKey.getEncoded();

			SubjectPublicKeyInfo vInfo = SubjectPublicKeyInfo.getInstance((new ASN1InputStream(bytes)).readObject());

			if (!vInfo.getAlgorithm().getParameters().Equals(DERNull.INSTANCE))
			{
				fail("public key parameters wrong");
			}

			ECPublicKey vKey = (ECPublicKey)kFact.generatePublic(new X509EncodedKeySpec(bytes));

			if (!vKey.Equals(pubKey) || vKey.GetHashCode() != pubKey.GetHashCode())
			{
				fail("public equals/hashCode failed");
			}

			testBCParamsAndQ(sKey, vKey);
			testEC5Params(sKey, vKey);

			testECDSA(sKey, vKey);
		}

		private void testBCParamsAndQ(ECPrivateKey sKey, ECPublicKey vKey)
		{
			if (sKey.getParameters() != null)
			{
				fail("parameters exposed in private key");
			}

			if (vKey.getParameters() != null)
			{
				fail("parameters exposed in public key");
			}

			if (vKey.getQ().getCurve() != null)
			{
				fail("curve exposed in public point");
			}
		}

		private void testEC5Params(ECPrivateKey sKey, ECPublicKey vKey)
		{
			ECKey k = (ECKey)sKey;

			if (k.getParams() != null)
			{
				fail("parameters exposed in private key");
			}

			k = (ECKey)vKey;
			if (k.getParams() != null)
			{
				fail("parameters exposed in public key");
			}
		}

		public override string getName()
		{
			return "ImplicitlyCA";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new ImplicitlyCaTest());
		}
	}

}