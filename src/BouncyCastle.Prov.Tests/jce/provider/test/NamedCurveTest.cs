using org.bouncycastle.jcajce.provider.config;

using System;

namespace org.bouncycastle.jce.provider.test
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ECGOST3410NamedCurves = org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
	using NISTNamedCurves = org.bouncycastle.asn1.nist.NISTNamedCurves;
	using SECNamedCurves = org.bouncycastle.asn1.sec.SECNamedCurves;
	using TeleTrusTNamedCurves = org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using X962NamedCurves = org.bouncycastle.asn1.x9.X962NamedCurves;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class NamedCurveTest : SimpleTest
	{
		private static Hashtable CURVE_NAMES = new Hashtable();
		private static Hashtable CURVE_ALIASES = new Hashtable();

		static NamedCurveTest()
		{
			CURVE_NAMES.put("prime192v1", "prime192v1"); // X9.62
			CURVE_NAMES.put("sect571r1", "sect571r1"); // sec
			CURVE_NAMES.put("secp224r1", "secp224r1");
			CURVE_NAMES.put("B-409", SECNamedCurves.getName(NISTNamedCurves.getOID("B-409"))); // nist
			CURVE_NAMES.put("P-521", SECNamedCurves.getName(NISTNamedCurves.getOID("P-521")));
			CURVE_NAMES.put("brainpoolP160r1", "brainpoolp160r1"); // TeleTrusT

			CURVE_ALIASES.put("secp192r1", "prime192v1");
			CURVE_ALIASES.put("secp256r1", "prime256v1");
		}

		public virtual void testCurve(string name)
		{
			ECGenParameterSpec ecSpec = new ECGenParameterSpec(name);

			KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");

			g.initialize(ecSpec, new SecureRandom());

			//
			// a side
			//
			KeyPair aKeyPair = g.generateKeyPair();

			KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDHC", "BC");

			aKeyAgree.init(aKeyPair.getPrivate());

			//
			// b side
			//
			KeyPair bKeyPair = g.generateKeyPair();

			KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDHC", "BC");

			bKeyAgree.init(bKeyPair.getPrivate());

			//
			// agreement
			//
			aKeyAgree.doPhase(bKeyPair.getPublic(), true);
			bKeyAgree.doPhase(aKeyPair.getPublic(), true);

			BigInteger k1 = new BigInteger(aKeyAgree.generateSecret());
			BigInteger k2 = new BigInteger(bKeyAgree.generateSecret());

			if (!k1.Equals(k2))
			{
				fail("2-way test failed");
			}

			//
			// public key encoding test
			//
			byte[] pubEnc = aKeyPair.getPublic().getEncoded();
			KeyFactory keyFac = KeyFactory.getInstance("ECDH", "BC");
			X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(pubEnc);
			ECPublicKey pubKey = (ECPublicKey)keyFac.generatePublic(pubX509);

			if (!pubKey.getW().Equals(((ECPublicKey)aKeyPair.getPublic()).getW()))
			{
				fail("public key encoding (Q test) failed");
			}

			if (!(pubKey.getParams() is ECNamedCurveSpec))
			{
				fail("public key encoding not named curve");
			}

			//
			// private key encoding test
			//
			byte[] privEnc = aKeyPair.getPrivate().getEncoded();
			PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
			ECPrivateKey privKey = (ECPrivateKey)keyFac.generatePrivate(privPKCS8);

			if (!privKey.getS().Equals(((ECPrivateKey)aKeyPair.getPrivate()).getS()))
			{
				fail("private key encoding (S test) failed");
			}

			if (!(privKey.getParams() is ECNamedCurveSpec))
			{
				fail("private key encoding not named curve");
			}

			ECNamedCurveSpec privSpec = (ECNamedCurveSpec)privKey.getParams();
			if (!(privSpec.getName().Equals(name) || privSpec.getName().Equals(CURVE_NAMES.get(name))))
			{
				fail("private key encoding wrong named curve. Expected: " + CURVE_NAMES.get(name) + " got " + privSpec.getName());
			}
		}

		public virtual void testECDSA(string name)
		{
			ECGenParameterSpec ecSpec = new ECGenParameterSpec(name);

			KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

			g.initialize(ecSpec, new SecureRandom());

			Signature sgr = Signature.getInstance("ECDSA", "BC");
			KeyPair pair = g.generateKeyPair();
			PrivateKey sKey = pair.getPrivate();
			PublicKey vKey = pair.getPublic();

			sgr.initSign(sKey);

			byte[] message = new byte[] {(byte)'a', (byte)'b', (byte)'c'};

			sgr.update(message);

			byte[] sigBytes = sgr.sign();

			sgr.initVerify(vKey);

			sgr.update(message);

			if (!sgr.verify(sigBytes))
			{
				fail(name + " verification failed");
			}

			//
			// public key encoding test
			//
			byte[] pubEnc = vKey.getEncoded();
			KeyFactory keyFac = KeyFactory.getInstance("ECDH", "BC");
			X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(pubEnc);
			ECPublicKey pubKey = (ECPublicKey)keyFac.generatePublic(pubX509);

			if (!pubKey.getW().Equals(((ECPublicKey)vKey).getW()))
			{
				fail("public key encoding (Q test) failed");
			}

			if (!(pubKey.getParams() is ECNamedCurveSpec))
			{
				fail("public key encoding not named curve");
			}

			//
			// private key encoding test
			//
			byte[] privEnc = sKey.getEncoded();
			PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
			ECPrivateKey privKey = (ECPrivateKey)keyFac.generatePrivate(privPKCS8);

			if (!privKey.getS().Equals(((ECPrivateKey)sKey).getS()))
			{
				fail("private key encoding (S test) failed");
			}

			if (!(privKey.getParams() is ECNamedCurveSpec))
			{
				fail("private key encoding not named curve");
			}

			ECNamedCurveSpec privSpec = (ECNamedCurveSpec)privKey.getParams();
			if (!privSpec.getName().Equals(name, StringComparison.OrdinalIgnoreCase) && !privSpec.getName().Equals((string)CURVE_ALIASES.get(name), StringComparison.OrdinalIgnoreCase))
			{
				fail("private key encoding wrong named curve. Expected: " + name + " got " + privSpec.getName());
			}
		}

		public virtual void testECGOST(string name)
		{
			ECGenParameterSpec ecSpec = new ECGenParameterSpec(name);

			KeyPairGenerator g;
			Signature sgr;
			string keyAlgorithm;

			if (name.StartsWith("Tc26-Gost-3410", StringComparison.Ordinal))
			{
				keyAlgorithm = "ECGOST3410-2012";
				if (name.IndexOf("256", StringComparison.Ordinal) > 0)
				{
					sgr = Signature.getInstance("ECGOST3410-2012-256", "BC");
				}
				else
				{
					sgr = Signature.getInstance("ECGOST3410-2012-512", "BC");
				}
			}
			else
			{
				keyAlgorithm = "ECGOST3410";

				sgr = Signature.getInstance("ECGOST3410", "BC");
			}

			g = KeyPairGenerator.getInstance(keyAlgorithm, "BC");

			g.initialize(ecSpec, new SecureRandom());

			KeyPair pair = g.generateKeyPair();
			PrivateKey sKey = pair.getPrivate();
			PublicKey vKey = pair.getPublic();

			sgr.initSign(sKey);

			byte[] message = new byte[] {(byte)'a', (byte)'b', (byte)'c'};

			sgr.update(message);

			byte[] sigBytes = sgr.sign();

			sgr.initVerify(vKey);

			sgr.update(message);

			if (!sgr.verify(sigBytes))
			{
				fail(name + " verification failed");
			}

			//
			// public key encoding test
			//
			byte[] pubEnc = vKey.getEncoded();
			KeyFactory keyFac = KeyFactory.getInstance(keyAlgorithm, "BC");
			X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(pubEnc);
			ECPublicKey pubKey = (ECPublicKey)keyFac.generatePublic(pubX509);

			if (!pubKey.getW().Equals(((ECPublicKey)vKey).getW()))
			{
				fail("public key encoding (Q test) failed");
			}

			if (!(pubKey.getParams() is ECNamedCurveSpec))
			{
				fail("public key encoding not named curve");
			}

			//
			// private key encoding test
			//
			byte[] privEnc = sKey.getEncoded();
			PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
			ECPrivateKey privKey = (ECPrivateKey)keyFac.generatePrivate(privPKCS8);

			if (!privKey.getS().Equals(((ECPrivateKey)sKey).getS()))
			{
				fail("GOST private key encoding (S test) failed");
			}

			if (!(privKey.getParams() is ECNamedCurveSpec))
			{
				fail("GOST private key encoding not named curve");
			}

			ECNamedCurveSpec privSpec = (ECNamedCurveSpec)privKey.getParams();
			if (!privSpec.getName().Equals(name, StringComparison.OrdinalIgnoreCase) && !privSpec.getName().Equals((string)CURVE_ALIASES.get(name), StringComparison.OrdinalIgnoreCase))
			{
				fail("GOST private key encoding wrong named curve. Expected: " + name + " got " + privSpec.getName());
			}
		}

		public virtual void testAcceptable()
		{
			ECGenParameterSpec ecSpec = new ECGenParameterSpec("P-256");
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

			kpGen.initialize(ecSpec);

			KeyPair kp = kpGen.generateKeyPair();

			X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
			PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

			KeyFactory kf = KeyFactory.getInstance("EC", "BC");

			ConfigurableProvider bcProv = ((ConfigurableProvider)Security.getProvider("BC"));

			bcProv.setParameter(ConfigurableProvider_Fields.ACCEPTABLE_EC_CURVES, Collections.singleton(NISTNamedCurves.getOID("P-384")));

			try
			{
				kf.generatePrivate(privSpec);
				fail("no exception");
			}
			catch (InvalidKeySpecException e)
			{
				isTrue("wrong message", "encoded key spec not recognized: named curve not acceptable".Equals(e.Message));
			}

			try
			{
				kf.generatePublic(pubSpec);
				fail("no exception");
			}
			catch (InvalidKeySpecException e)
			{
				isTrue("wrong message", "encoded key spec not recognized: named curve not acceptable".Equals(e.Message));
			}

			bcProv.setParameter(ConfigurableProvider_Fields.ACCEPTABLE_EC_CURVES, Collections.singleton(NISTNamedCurves.getOID("P-256")));

			kf.generatePrivate(privSpec);
			kf.generatePublic(pubSpec);

			bcProv.setParameter(ConfigurableProvider_Fields.ACCEPTABLE_EC_CURVES, Collections.EMPTY_SET);

			kf.generatePrivate(privSpec);
			kf.generatePublic(pubSpec);
		}

		public virtual void testAdditional()
		{
			ConfigurableProvider bcProv = ((ConfigurableProvider)Security.getProvider("BC"));
			ASN1ObjectIdentifier bogusCurveID = Extension.auditIdentity;

			bcProv.setParameter(ConfigurableProvider_Fields.ADDITIONAL_EC_PARAMETERS, Collections.singletonMap(bogusCurveID, NISTNamedCurves.getByName("P-384")));

			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

			kpGen.initialize(new ECGenParameterSpec(bogusCurveID.getId()));

			KeyPair kp = kpGen.generateKeyPair();

			X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
			PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

			KeyFactory kf = KeyFactory.getInstance("EC", "BC");

			kf.generatePrivate(privSpec);
			kf.generatePublic(pubSpec);
		}

		public override string getName()
		{
			return "NamedCurve";
		}

		public override void performTest()
		{
			testCurve("prime192v1"); // X9.62
			testCurve("sect571r1"); // sec
			testCurve("secp224r1");
			testCurve("B-409"); // nist
			testCurve("P-521");
			testCurve("brainpoolP160r1"); // TeleTrusT

			for (Enumeration en = X962NamedCurves.getNames(); en.hasMoreElements();)
			{
				testECDSA((string)en.nextElement());
			}

			// these curves can't be used under JDK 1.5
			Set problemCurves = new HashSet();

			problemCurves.add("secp256k1");
			problemCurves.add("secp160k1");
			problemCurves.add("secp224k1");
			problemCurves.add("secp192k1");

			for (Enumeration en = SECNamedCurves.getNames(); en.hasMoreElements();)
			{
				string curveName = (string)en.nextElement();

				if (!problemCurves.contains(curveName))
				{
					testECDSA(curveName);
				}
			}

			for (Enumeration en = TeleTrusTNamedCurves.getNames(); en.hasMoreElements();)
			{
				testECDSA((string)en.nextElement());
			}

			for (Enumeration en = ECGOST3410NamedCurves.getNames(); en.hasMoreElements();)
			{
				testECGOST((string)en.nextElement());
			}

			testAcceptable();
			testAdditional();
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new NamedCurveTest());
		}
	}

}