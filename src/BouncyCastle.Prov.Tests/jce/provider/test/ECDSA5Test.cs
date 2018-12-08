using org.bouncycastle.jce.spec;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.eac;
using org.bouncycastle.asn1.bsi;
using org.bouncycastle.asn1.sec;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jce.provider.test
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using BSIObjectIdentifiers = org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;
	using NISTNamedCurves = org.bouncycastle.asn1.nist.NISTNamedCurves;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SECObjectIdentifiers = org.bouncycastle.asn1.sec.SECObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using MQVParameterSpec = org.bouncycastle.jcajce.spec.MQVParameterSpec;
	using ECNamedCurveGenParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
	using ECNamedCurveParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using Arrays = org.bouncycastle.util.Arrays;
	using BigIntegers = org.bouncycastle.util.BigIntegers;
	using Strings = org.bouncycastle.util.Strings;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using FixedSecureRandom = org.bouncycastle.util.test.FixedSecureRandom;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using TestRandomBigInteger = org.bouncycastle.util.test.TestRandomBigInteger;

	public class ECDSA5Test : SimpleTest
	{
		private bool InstanceFieldsInitialized = false;

		public ECDSA5Test()
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

		private static readonly byte[] namedPubKey = Base64.decode("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEJMeqHZzm+saHt1m3a4u5BIqgSznd8LNvoeS93zzE9Ll31/AMaveAj" + "JqWxGdyCwnqmM5m3IFCZV3abKVGNpnuQwhIOPMm1355YX1JeEy/ifCx7lYe1o8Xs/Ajqz8cJB3j");

		internal byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
		internal byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

		internal SecureRandom random;
		internal static readonly BigInteger PubX = new BigInteger("3390396496586153202365024500890309020181905168626402195853036609" + "0984128098564");
		internal static readonly BigInteger PubY = new BigInteger("1135421298983937257390683162600855221890652900790509030911087400" + "65052129055287");
		internal static readonly string[] VALID_SIGNATURES = new string[] {"3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49" + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285" + "cd59f43260ecce"};

		// The following test vectors check for signature malleability and bugs. That means the test
		// vectors are derived from a valid signature by modifying the ASN encoding. A correct
		// implementation of ECDSA should only accept correct DER encoding and properly handle the
		// others (e.g. integer overflow, infinity, redundant parameters, etc). Allowing alternative BER
		// encodings is in many cases benign. An example where this kind of signature malleability was a
		// problem: https://en.bitcoin.it/wiki/Transaction_Malleability
		internal static readonly string[] MODIFIED_SIGNATURES = new string[] {"304602812100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f" + "3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce", "30470282002100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd" + "2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce", "304602220000b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f" + "3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce", "3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f028120747291dd2f" + "3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce", "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f02820020747291dd" + "2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce", "3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f022100747291dd2f" + "3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce", "308145022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f" + "3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce", "30820045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd" + "2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce", "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f" + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce3000", "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f" + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce1000", "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f" + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0000", "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f" + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0000", "3048022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f" + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce058100", "3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f" + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce05820000", "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f" + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce1100", "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f" + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0500", "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f" + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce2500", "3067022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f" + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0220747291dd2f3f44af7ace68ea33431d6f" + "94e418c106a6e76285cd59f43260ecce"};

		private void testModified()
		{
			ECNamedCurveParameterSpec namedCurve = ECNamedCurveTable.getParameterSpec("P-256");
			ECPublicKeySpec pubSpec = new ECPublicKeySpec(namedCurve.getCurve().createPoint(PubX, PubY), namedCurve);
			KeyFactory kFact = KeyFactory.getInstance("EC", "BC");
			PublicKey pubKey = kFact.generatePublic(pubSpec);
			Signature sig = Signature.getInstance("SHA256WithECDSA", "BC");

			for (int i = 0; i != MODIFIED_SIGNATURES.Length; i++)
			{
				sig.initVerify(pubKey);

				sig.update(Strings.toByteArray("Hello"));

				bool failed;

				try
				{
					failed = !sig.verify(Hex.decode(MODIFIED_SIGNATURES[i]));
				}
				catch (SignatureException)
				{
					failed = true;
				}

				isTrue("sig verified when shouldn't: " + i, failed);
			}
		}

		public virtual void testNamedCurveInKeyFactory()
		{
			KeyFactory kfBc = KeyFactory.getInstance("EC", "BC");
			BigInteger x = new BigInteger("24c7aa1d9ce6fac687b759b76b8bb9048aa04b39ddf0b36fa1e4bddf3cc4f4b977d7f00c6af7808c9a96c467720b09ea", 16);
			BigInteger y = new BigInteger("98ce66dc8142655dda6ca5463699ee43084838f326d77e79617d49784cbf89f0b1ee561ed68f17b3f023ab3f1c241de3", 16);
			string curveName = "secp384r1";
			ECPoint point = new ECPoint(x, y);

			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "BC");
			parameters.init(new ECGenParameterSpec(curveName));
			ECParameterSpec ecParamSpec = parameters.getParameterSpec(typeof(ECParameterSpec));
			PublicKey pubKey = kfBc.generatePublic(new ECPublicKeySpec(point, ecParamSpec));

			isTrue(Arrays.areEqual(namedPubKey, pubKey.getEncoded()));
		}

		private void decodeTest()
		{
			EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger("6277101735386680763835789423207666416083908700390324961279")), new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16)); // b

			ECPoint p = ECPointUtil.decodePoint(curve, Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"));

			if (!p.getAffineX().Equals(new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16)))
			{
				fail("x uncompressed incorrectly");
			}

			if (!p.getAffineY().Equals(new BigInteger("7192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16)))
			{
				fail("y uncompressed incorrectly");
			}
		}

		/// <summary>
		/// X9.62 - 1998,<br>
		/// J.3.2, Page 155, ECDSA over the field Fp<br>
		/// an example with 239 bit prime
		/// </summary>
		private void testECDSA239bitPrime()
		{
			BigInteger r = new BigInteger("308636143175167811492622547300668018854959378758531778147462058306432176");
			BigInteger s = new BigInteger("323813553209797357708078776831250505931891051755007842781978505179448783");

			byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));

			SecureRandom k = new TestRandomBigInteger(kData);

			EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

			ECParameterSpec spec = new ECParameterSpec(curve, ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), 1); // h


			ECPrivateKeySpec priKey = new ECPrivateKeySpec(new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), spec);

			ECPublicKeySpec pubKey = new ECPublicKeySpec(ECPointUtil.decodePoint(curve, Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), spec);

			Signature sgr = Signature.getInstance("ECDSA", "BC");
			KeyFactory f = KeyFactory.getInstance("ECDSA", "BC");
			PrivateKey sKey = f.generatePrivate(priKey);
			PublicKey vKey = f.generatePublic(pubKey);

			sgr.initSign(sKey, k);

			byte[] message = new byte[]{(byte)'a', (byte)'b', (byte)'c'};

			sgr.update(message);

			byte[] sigBytes = sgr.sign();

			sgr.initVerify(vKey);

			sgr.update(message);

			if (!sgr.verify(sigBytes))
			{
				fail("239 Bit EC verification failed");
			}

			BigInteger[] sig = derDecode(sigBytes);

			if (!r.Equals(sig[0]))
			{
				fail("r component wrong." + Strings.lineSeparator() + " expecting: " + r + Strings.lineSeparator() + " got      : " + sig[0]);
			}

			if (!s.Equals(sig[1]))
			{
				fail("s component wrong." + Strings.lineSeparator() + " expecting: " + s + Strings.lineSeparator() + " got      : " + sig[1]);
			}
		}

		private void testSM2()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

			kpGen.initialize(new ECGenParameterSpec("sm2p256v1"));

			KeyPair kp = kpGen.generateKeyPair();

			kpGen.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));

			kp = kpGen.generateKeyPair();
		}

		private void testNonsense()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

			try
			{
				kpGen.initialize(new ECGenParameterSpec("no_such_curve"));
				fail("no exception");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				isEquals("unknown curve name: no_such_curve", e.Message);
			}
			KeyPair kp = kpGen.generateKeyPair();

			try
			{
				kpGen.initialize(new ECNamedCurveGenParameterSpec("1.2.3.4.5"));
				fail("no exception");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				isEquals("unknown curve OID: 1.2.3.4.5", e.Message);
			}

			kp = kpGen.generateKeyPair();
		}

		// test BSI algorithm support.
		private void testBSI()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

			kpGen.initialize(new ECGenParameterSpec(TeleTrusTObjectIdentifiers_Fields.brainpoolP512r1.getId()));

			KeyPair kp = kpGen.generateKeyPair();

			byte[] data = "Hello World!!!".GetBytes();
			string[] cvcAlgs = new string[] {"SHA1WITHCVC-ECDSA", "SHA224WITHCVC-ECDSA", "SHA256WITHCVC-ECDSA", "SHA384WITHCVC-ECDSA", "SHA512WITHCVC-ECDSA"};
			string[] cvcOids = new string[] {EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_1.getId(), EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_224.getId(), EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_256.getId(), EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_384.getId(), EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_512.getId()};

			testBsiAlgorithms(kp, data, cvcAlgs, cvcOids);

			string[] plainAlgs = new string[] {"SHA1WITHPLAIN-ECDSA", "SHA224WITHPLAIN-ECDSA", "SHA256WITHPLAIN-ECDSA", "SHA384WITHPLAIN-ECDSA", "SHA512WITHPLAIN-ECDSA", "RIPEMD160WITHPLAIN-ECDSA"};
			string[] plainOids = new string[] {BSIObjectIdentifiers_Fields.ecdsa_plain_SHA1.getId(), BSIObjectIdentifiers_Fields.ecdsa_plain_SHA224.getId(), BSIObjectIdentifiers_Fields.ecdsa_plain_SHA256.getId(), BSIObjectIdentifiers_Fields.ecdsa_plain_SHA384.getId(), BSIObjectIdentifiers_Fields.ecdsa_plain_SHA512.getId(), BSIObjectIdentifiers_Fields.ecdsa_plain_RIPEMD160.getId()};

			testBsiAlgorithms(kp, data, plainAlgs, plainOids);

			kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

			kpGen.initialize(new ECGenParameterSpec(SECObjectIdentifiers_Fields.secp521r1.getId()));

			kp = kpGen.generateKeyPair();

			ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(SECObjectIdentifiers_Fields.secp521r1.getId());
			testBsiSigSize(kp, spec.getN(), "SHA224WITHPLAIN-ECDSA");
		}

		private void testBsiAlgorithms(KeyPair kp, byte[] data, string[] algs, string[] oids)
		{
			for (int i = 0; i != algs.Length; i++)
			{
				Signature sig1 = Signature.getInstance(algs[i], "BC");
				Signature sig2 = Signature.getInstance(oids[i], "BC");

				sig1.initSign(kp.getPrivate());

				sig1.update(data);

				byte[] sig = sig1.sign();

				sig2.initVerify(kp.getPublic());

				sig2.update(data);

				if (!sig2.verify(sig))
				{
					fail("BSI CVC signature failed: " + algs[i]);
				}
			}
		}

		private void testBsiSigSize(KeyPair kp, BigInteger order, string alg)
		{
			for (int i = 0; i != 20; i++)
			{
				Signature sig1 = Signature.getInstance(alg, "BC");
				Signature sig2 = Signature.getInstance(alg, "BC");

				sig1.initSign(kp.getPrivate());

				sig1.update(new byte[]{(byte)i});

				byte[] sig = sig1.sign();

				isTrue(sig.Length == (2 * ((order.bitLength() + 7) / 8)));
				sig2.initVerify(kp.getPublic());

				sig2.update(new byte[]{(byte)i});

				if (!sig2.verify(sig))
				{
					fail("BSI CVC signature failed: " + alg);
				}
			}
		}

		/// <summary>
		/// X9.62 - 1998,<br>
		/// J.2.1, Page 100, ECDSA over the field F2m<br>
		/// an example with 191 bit binary field
		/// </summary>
		private void testECDSA239bitBinary()
		{
			BigInteger r = new BigInteger("21596333210419611985018340039034612628818151486841789642455876922391552");
			BigInteger s = new BigInteger("197030374000731686738334997654997227052849804072198819102649413465737174");

			byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("171278725565216523967285789236956265265265235675811949404040041670216363"));

			SecureRandom k = new TestRandomBigInteger(kData);

			EllipticCurve curve = new EllipticCurve(new ECFieldF2m(239, new int[]{36}), new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16)); // b

			ECParameterSpec @params = new ECParameterSpec(curve, ECPointUtil.decodePoint(curve, Hex.decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783"), 4); // h

			ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), @params);

			ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ECPointUtil.decodePoint(curve, Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), @params);

			Signature sgr = Signature.getInstance("ECDSA", "BC");
			KeyFactory f = KeyFactory.getInstance("ECDSA", "BC");
			PrivateKey sKey = f.generatePrivate(priKeySpec);
			PublicKey vKey = f.generatePublic(pubKeySpec);
			byte[] message = new byte[]{(byte)'a', (byte)'b', (byte)'c'};

			sgr.initSign(sKey, k);

			sgr.update(message);

			byte[] sigBytes = sgr.sign();

			sgr.initVerify(vKey);

			sgr.update(message);

			if (!sgr.verify(sigBytes))
			{
				fail("239 Bit EC verification failed");
			}

			BigInteger[] sig = derDecode(sigBytes);

			if (!r.Equals(sig[0]))
			{
				fail("r component wrong." + Strings.lineSeparator() + " expecting: " + r + Strings.lineSeparator() + " got      : " + sig[0]);
			}

			if (!s.Equals(sig[1]))
			{
				fail("s component wrong." + Strings.lineSeparator() + " expecting: " + s + Strings.lineSeparator() + " got      : " + sig[1]);
			}
		}

		private void testGeneration()
		{
			//
			// ECDSA generation test
			//
			byte[] data = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
			Signature s = Signature.getInstance("ECDSA", "BC");
			KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

			EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

			ECParameterSpec ecSpec = new ECParameterSpec(curve, ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), 1); // h

			g.initialize(ecSpec, new SecureRandom());

			KeyPair p = g.generateKeyPair();

			PrivateKey sKey = p.getPrivate();
			PublicKey vKey = p.getPublic();

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

			testKeyFactory((ECPublicKey)vKey, (ECPrivateKey)sKey);
			testSerialise((ECPublicKey)vKey, (ECPrivateKey)sKey);
		}

		private void testSerialise(ECPublicKey ecPublicKey, ECPrivateKey ecPrivateKey)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ObjectOutputStream oOut = new ObjectOutputStream(bOut);

			oOut.writeObject(ecPublicKey);
			oOut.writeObject(ecPrivateKey);
			oOut.close();

			ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

			PublicKey pubKey = (PublicKey)oIn.readObject();
			PrivateKey privKey = (PrivateKey)oIn.readObject();

			if (!ecPublicKey.Equals(pubKey))
			{
				fail("public key serialisation check failed");
			}

			if (!ecPrivateKey.Equals(privKey))
			{
				fail("private key serialisation check failed");
			}
		}

		private void testKeyFactory(ECPublicKey pub, ECPrivateKey priv)
		{
			KeyFactory ecFact = KeyFactory.getInstance("ECDSA");

			ECPublicKeySpec pubSpec = (ECPublicKeySpec)ecFact.getKeySpec(pub, typeof(ECPublicKeySpec));
			ECPrivateKeySpec privSpec = (ECPrivateKeySpec)ecFact.getKeySpec(priv, typeof(ECPrivateKeySpec));

			if (!pubSpec.getW().Equals(pub.getW()) || !pubSpec.getParams().getCurve().Equals(pub.getParams().getCurve()))
			{
				fail("pubSpec not correct");
			}

			if (!privSpec.getS().Equals(priv.getS()) || !privSpec.getParams().getCurve().Equals(priv.getParams().getCurve()))
			{
				fail("privSpec not correct");
			}

			ECPublicKey pubKey = (ECPublicKey)ecFact.translateKey(pub);
			ECPrivateKey privKey = (ECPrivateKey)ecFact.translateKey(priv);

			if (!pubKey.getW().Equals(pub.getW()) || !pubKey.getParams().getCurve().Equals(pub.getParams().getCurve()))
			{
				fail("pubKey not correct");
			}

			if (!privKey.getS().Equals(priv.getS()) || !privKey.getParams().getCurve().Equals(priv.getParams().getCurve()))
			{
				fail("privKey not correct");
			}
		}

		private void testKeyConversion()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

			kpGen.initialize(new ECGenParameterSpec("prime192v1"));

			KeyPair pair = kpGen.generateKeyPair();

			PublicKey pubKey = ECKeyUtil.publicToExplicitParameters(pair.getPublic(), "BC");

			SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pubKey.getEncoded()));
			X962Parameters @params = X962Parameters.getInstance(info.getAlgorithm().getParameters());

			if (@params.isNamedCurve() || @params.isImplicitlyCA())
			{
				fail("public key conversion to explicit failed");
			}

			if (!((ECPublicKey)pair.getPublic()).getW().Equals(((ECPublicKey)pubKey).getW()))
			{
				fail("public key conversion check failed");
			}

			PrivateKey privKey = ECKeyUtil.privateToExplicitParameters(pair.getPrivate(), "BC");
			PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privKey.getEncoded()));
			@params = X962Parameters.getInstance(privInfo.getPrivateKeyAlgorithm().getParameters());

			if (@params.isNamedCurve() || @params.isImplicitlyCA())
			{
				fail("private key conversion to explicit failed");
			}

			if (!((ECPrivateKey)pair.getPrivate()).getS().Equals(((ECPrivateKey)privKey).getS()))
			{
				fail("private key conversion check failed");
			}
		}

		private void testAdaptiveKeyConversion()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

			kpGen.initialize(new ECGenParameterSpec("prime192v1"));

			KeyPair pair = kpGen.generateKeyPair();

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.PrivateKey privKey = pair.getPrivate();
			PrivateKey privKey = pair.getPrivate();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.PublicKey pubKey = pair.getPublic();
			PublicKey pubKey = pair.getPublic();

			Signature s = Signature.getInstance("ECDSA", "BC");

			// raw interface tests
			s.initSign(new PrivateKeyAnonymousInnerClass(this, privKey));

			s.initVerify(new PublicKeyAnonymousInnerClass(this, pubKey));


			s.initSign(new ECPrivateKeyAnonymousInnerClass(this, privKey));

			s.initVerify(new ECPublicKeyAnonymousInnerClass(this, pubKey));

			try
			{
				s.initSign(new PrivateKeyAnonymousInnerClass2(this, privKey));

				fail("no exception thrown!!!");
			}
			catch (InvalidKeyException)
			{
				// ignore
			}

			try
			{
				s.initVerify(new PublicKeyAnonymousInnerClass2(this, pubKey));

				fail("no exception thrown!!!");
			}
			catch (InvalidKeyException)
			{
				// ignore
			}

			// try bogus encoding
			try
			{
				s.initSign(new PrivateKeyAnonymousInnerClass3(this, privKey));

				fail("no exception thrown!!!");
			}
			catch (InvalidKeyException)
			{
				// ignore
			}

			try
			{
				s.initVerify(new PublicKeyAnonymousInnerClass3(this, pubKey));

				fail("no exception thrown!!!");
			}
			catch (InvalidKeyException)
			{
				// ignore
			}

			// try encoding of wrong key
			kpGen = KeyPairGenerator.getInstance("RSA", "BC");

			kpGen.initialize(512);

			pair = kpGen.generateKeyPair();

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.PrivateKey privRsa = pair.getPrivate();
			PrivateKey privRsa = pair.getPrivate();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.PublicKey pubRsa = pair.getPublic();
			PublicKey pubRsa = pair.getPublic();

			try
			{
				s.initSign(new PrivateKeyAnonymousInnerClass4(this, privRsa));

				fail("no exception thrown!!!");

			}
			catch (InvalidKeyException)
			{
				// ignore
			}

			try
			{
				s.initVerify(new PublicKeyAnonymousInnerClass4(this, pubRsa));

				fail("no exception thrown!!!");
			}
			catch (InvalidKeyException)
			{
				// ignore
			}
		}

		public class PrivateKeyAnonymousInnerClass : PrivateKey
		{
			private readonly ECDSA5Test outerInstance;

			private PrivateKey privKey;

			public PrivateKeyAnonymousInnerClass(ECDSA5Test outerInstance, PrivateKey privKey)
			{
				this.outerInstance = outerInstance;
				this.privKey = privKey;
			}

			public string getAlgorithm()
			{
				return privKey.getAlgorithm();
			}

			public string getFormat()
			{
				return privKey.getFormat();
			}

			public byte[] getEncoded()
			{
				return privKey.getEncoded();
			}
		}

		public class PublicKeyAnonymousInnerClass : PublicKey
		{
			private readonly ECDSA5Test outerInstance;

			private PublicKey pubKey;

			public PublicKeyAnonymousInnerClass(ECDSA5Test outerInstance, PublicKey pubKey)
			{
				this.outerInstance = outerInstance;
				this.pubKey = pubKey;
			}

			public string getAlgorithm()
			{
				return pubKey.getAlgorithm();
			}

			public string getFormat()
			{
				return pubKey.getFormat();
			}

			public byte[] getEncoded()
			{
				return pubKey.getEncoded();
			}
		}

		public class ECPrivateKeyAnonymousInnerClass : ECPrivateKey
		{
			private readonly ECDSA5Test outerInstance;

			private PrivateKey privKey;

			public ECPrivateKeyAnonymousInnerClass(ECDSA5Test outerInstance, PrivateKey privKey)
			{
				this.outerInstance = outerInstance;
				this.privKey = privKey;
			}

			public string getAlgorithm()
			{
				return privKey.getAlgorithm();
			}

			public string getFormat()
			{
				return privKey.getFormat();
			}

			public byte[] getEncoded()
			{
				return privKey.getEncoded();
			}

			public BigInteger getS()
			{
				return ((ECPrivateKey)privKey).getS();
			}

			public ECParameterSpec getParams()
			{
				return ((ECPrivateKey)privKey).getParams();
			}
		}

		public class ECPublicKeyAnonymousInnerClass : ECPublicKey
		{
			private readonly ECDSA5Test outerInstance;

			private PublicKey pubKey;

			public ECPublicKeyAnonymousInnerClass(ECDSA5Test outerInstance, PublicKey pubKey)
			{
				this.outerInstance = outerInstance;
				this.pubKey = pubKey;
			}

			public string getAlgorithm()
			{
				return pubKey.getAlgorithm();
			}

			public string getFormat()
			{
				return pubKey.getFormat();
			}

			public byte[] getEncoded()
			{
				return pubKey.getEncoded();
			}

			public ECPoint getW()
			{
				return ((ECPublicKey)pubKey).getW();
			}

			public ECParameterSpec getParams()
			{
				return ((ECPublicKey)pubKey).getParams();
			}
		}

		public class PrivateKeyAnonymousInnerClass2 : PrivateKey
		{
			private readonly ECDSA5Test outerInstance;

			private PrivateKey privKey;

			public PrivateKeyAnonymousInnerClass2(ECDSA5Test outerInstance, PrivateKey privKey)
			{
				this.outerInstance = outerInstance;
				this.privKey = privKey;
			}

			public string getAlgorithm()
			{
				return privKey.getAlgorithm();
			}

			public string getFormat()
			{
				return privKey.getFormat();
			}

			public byte[] getEncoded()
			{
				return null;
			}
		}

		public class PublicKeyAnonymousInnerClass2 : PublicKey
		{
			private readonly ECDSA5Test outerInstance;

			private PublicKey pubKey;

			public PublicKeyAnonymousInnerClass2(ECDSA5Test outerInstance, PublicKey pubKey)
			{
				this.outerInstance = outerInstance;
				this.pubKey = pubKey;
			}

			public string getAlgorithm()
			{
				return pubKey.getAlgorithm();
			}

			public string getFormat()
			{
				return pubKey.getFormat();
			}

			public byte[] getEncoded()
			{
				return null;
			}
		}

		public class PrivateKeyAnonymousInnerClass3 : PrivateKey
		{
			private readonly ECDSA5Test outerInstance;

			private PrivateKey privKey;

			public PrivateKeyAnonymousInnerClass3(ECDSA5Test outerInstance, PrivateKey privKey)
			{
				this.outerInstance = outerInstance;
				this.privKey = privKey;
			}

			public string getAlgorithm()
			{
				return privKey.getAlgorithm();
			}

			public string getFormat()
			{
				return privKey.getFormat();
			}

			public byte[] getEncoded()
			{
				return new byte[20];
			}
		}

		public class PublicKeyAnonymousInnerClass3 : PublicKey
		{
			private readonly ECDSA5Test outerInstance;

			private PublicKey pubKey;

			public PublicKeyAnonymousInnerClass3(ECDSA5Test outerInstance, PublicKey pubKey)
			{
				this.outerInstance = outerInstance;
				this.pubKey = pubKey;
			}

			public string getAlgorithm()
			{
				return pubKey.getAlgorithm();
			}

			public string getFormat()
			{
				return pubKey.getFormat();
			}

			public byte[] getEncoded()
			{
				return new byte[20];
			}
		}

		public class PrivateKeyAnonymousInnerClass4 : PrivateKey
		{
			private readonly ECDSA5Test outerInstance;

			private PrivateKey privRsa;

			public PrivateKeyAnonymousInnerClass4(ECDSA5Test outerInstance, PrivateKey privRsa)
			{
				this.outerInstance = outerInstance;
				this.privRsa = privRsa;
			}

			public string getAlgorithm()
			{
				return privRsa.getAlgorithm();
			}

			public string getFormat()
			{
				return privRsa.getFormat();
			}

			public byte[] getEncoded()
			{
				return privRsa.getEncoded();
			}
		}

		public class PublicKeyAnonymousInnerClass4 : PublicKey
		{
			private readonly ECDSA5Test outerInstance;

			private PublicKey pubRsa;

			public PublicKeyAnonymousInnerClass4(ECDSA5Test outerInstance, PublicKey pubRsa)
			{
				this.outerInstance = outerInstance;
				this.pubRsa = pubRsa;
			}

			public string getAlgorithm()
			{
				return pubRsa.getAlgorithm();
			}

			public string getFormat()
			{
				return pubRsa.getFormat();
			}

			public byte[] getEncoded()
			{
				return pubRsa.getEncoded();
			}
		}

		private void testAlgorithmParameters()
		{
			AlgorithmParameters algParam = AlgorithmParameters.getInstance("EC", "BC");

			algParam.init(new ECGenParameterSpec("P-256"));

			byte[] encoded = algParam.getEncoded();

			algParam = AlgorithmParameters.getInstance("EC", "BC");

			algParam.init(encoded);

			ECGenParameterSpec genSpec = algParam.getParameterSpec(typeof(ECGenParameterSpec));

			if (!genSpec.getName().Equals(X9ObjectIdentifiers_Fields.prime256v1.getId()))
			{
				fail("curve name not recovered");
			}

			ECParameterSpec ecSpec = algParam.getParameterSpec(typeof(ECParameterSpec));

			if (!ecSpec.getOrder().Equals(NISTNamedCurves.getByName("P-256").getN()))
			{
				fail("incorrect spec recovered");
			}
		}

		private void testKeyPairGenerationWithOIDs()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

			kpGen.initialize(new ECGenParameterSpec(X9ObjectIdentifiers_Fields.prime192v1.getId()));
			kpGen.initialize(new ECGenParameterSpec(TeleTrusTObjectIdentifiers_Fields.brainpoolP160r1.getId()));
			kpGen.initialize(new ECGenParameterSpec(SECObjectIdentifiers_Fields.secp128r1.getId()));

			try
			{
				kpGen.initialize(new ECGenParameterSpec("1.1"));

				fail("non-existant curve OID failed");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				if (!"unknown curve OID: 1.1".Equals(e.Message))
				{
					fail("OID message check failed");
				}
			}

			try
			{
				kpGen.initialize(new ECGenParameterSpec("flibble"));

				fail("non-existant curve name failed");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				if (!"unknown curve name: flibble".Equals(e.Message))
				{
					fail("name message check failed");
				}
			}
		}

		public class ECRandom : SecureRandom
		{
			public virtual void nextBytes(byte[] bytes)
			{
				byte[] src = (new BigInteger("e2eb6663f551331bda00b90f1272c09d980260c1a70cab1ec481f6c937f34b62", 16)).toByteArray();

				if (src.Length <= bytes.Length)
				{
					JavaSystem.arraycopy(src, 0, bytes, bytes.Length - src.Length, src.Length);
				}
				else
				{
					JavaSystem.arraycopy(src, 0, bytes, 0, bytes.Length);
				}
			}
		}

		private void testNamedCurveParameterPreservation()
		{
			AlgorithmParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
			KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC", "BC");
			keygen.initialize(ecSpec, new ECRandom());

			KeyPair keys = keygen.generateKeyPair();

			PrivateKeyInfo priv1 = PrivateKeyInfo.getInstance(keys.getPrivate().getEncoded());
			SubjectPublicKeyInfo pub1 = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());

			keygen = KeyPairGenerator.getInstance("EC", "BC");
			keygen.initialize(new ECGenParameterSpec("secp256r1"), new ECRandom());

			PrivateKeyInfo priv2 = PrivateKeyInfo.getInstance(keys.getPrivate().getEncoded());
			SubjectPublicKeyInfo pub2 = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());

			if (!priv1.Equals(priv2) || !pub1.Equals(pub2))
			{
				fail("mismatch between alg param spec and ECGenParameterSpec");
			}

			if (!(priv2.getPrivateKeyAlgorithm().getParameters() is ASN1ObjectIdentifier))
			{
				fail("OID not preserved in private key");
			}

			if (!(pub1.getAlgorithm().getParameters() is ASN1ObjectIdentifier))
			{
				fail("OID not preserved in public key");
			}
		}

		private void testNamedCurveSigning()
		{
			testCustomNamedCurveSigning("secp256r1");

			try
			{
				testCustomNamedCurveSigning("secp256k1");
			}
			catch (IllegalArgumentException e)
			{
				if (!e.getMessage().Equals("first coefficient is negative")) // bogus jdk 1.5 exception...
				{
					throw e;
				}
			}
		}

		private void testCustomNamedCurveSigning(string name)
		{
			X9ECParameters x9Params = ECUtil.getNamedCurveByOid(ECUtil.getNamedCurveOid(name));

			// TODO: one day this may have to change
			if (x9Params.getCurve() is ECCurve.Fp)
			{
				fail("curve not custom curve!!");
			}

			AlgorithmParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(name);
			KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC", "BC");
			keygen.initialize(ecSpec, new ECRandom());

			KeyPair keys = keygen.generateKeyPair();

			PrivateKeyInfo priv1 = PrivateKeyInfo.getInstance(keys.getPrivate().getEncoded());
			SubjectPublicKeyInfo pub1 = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());

			keygen = KeyPairGenerator.getInstance("EC", "BC");
			keygen.initialize(new ECGenParameterSpec("secp256r1"), new ECRandom());

			Signature ecdsaSigner = Signature.getInstance("ECDSA", "BC");

			ecdsaSigner.initSign(keys.getPrivate());

			ecdsaSigner.update(new byte[100]);

			byte[] sig = ecdsaSigner.sign();

			ecdsaSigner.initVerify(keys.getPublic());

			ecdsaSigner.update(new byte[100]);

			if (!ecdsaSigner.verify(sig))
			{
				fail("signature failed to verify");
			}

			KeyFactory kFact = KeyFactory.getInstance("EC", "BC");

			PublicKey pub = kFact.generatePublic(new X509EncodedKeySpec(pub1.getEncoded()));
			PrivateKey pri = kFact.generatePrivate(new PKCS8EncodedKeySpec(priv1.getEncoded()));

			ecdsaSigner = Signature.getInstance("ECDSA", "BC");

			ecdsaSigner.initSign(pri);

			ecdsaSigner.update(new byte[100]);

			sig = ecdsaSigner.sign();

			ecdsaSigner.initVerify(pub);

			ecdsaSigner.update(new byte[100]);

			if (!ecdsaSigner.verify(sig))
			{
				fail("signature failed to verify");
			}
		}

		/// <summary>
		/// COUNT = 1
		/// dsCAVS = 00000179557decd75b797bea9db656ce99c03a6e0ab13804b5b589644f7db41ceba05c3940c300361061074ca72a828428d9198267fa0b75e1e3e785a0ff20e839414be0
		/// QsCAVSx = 000001ce7da31681d5f176f3618f205969b9142520363dd26a596866c89988c932e3ce01904d12d1e9b105462e56163dbe7658ba3c472bf1f3c8165813295393ae346764
		/// QsCAVSy = 000000e70d6e55b76ebd362ff071ab819315593cec650276209a9fdc2c1c48e03c35945f04e74d958cabd3f5e4d1f096a991e807a8f9d217de306a6b561038ca15aea4b9
		/// NonceEphemCAVS = 4214a1a0a1d11679ae22f98d7ae483c1a74008a9cd7f7cf71b1f373a4226f5c58eb621ec56e2537797c01750dcbff07f613b9c58774f9af32aebeadd2226140dc7d56b1aa95c93ab1ec4412e2d0e42cdaac7bf9da3ddbf19fbb1edd0556d9c5a339808905fe8defd8b57ff8f34788192cc0cf7df17d1f351d69ac979a3a495931c287fb8
		/// dsIUT = 000000c14895dfcc5a6b24994828cfd0a0cc0a881a70173a3eb05c57b098046c8e60a868f6176284aa346eff1fd1b8b879052c5a6d5fd0ae146b35ed7ecee32e294103cd
		/// QsIUTx = 00000174a658695049db59f6bbe2ad23e1753bf58384a56fc9b3dec13eb873b33e1f4dbd24b6b4ca05a9a11ad531f6d99e9430a774980e8a8d9fd2d1e2a0d76fe3dd36c7
		/// QsIUTy = 00000030639849e1df341973db44e7bbba5bb597884a439f9ce54620c3ca73a9804cc26fcda3aaf73ae5a11d5b325cae0e95cfafe1985c6c2fdb892722e7dd2c5d744cf3
		/// deIUT = 00000138f54e986c7b44f49da389fa9f61bb7265f0cebdeddf09d47c72e55186e2520965fc2c31bb9c0a557e3c28e02a751f097e413c4252c7b0d22452d89f9ac314bc6e
		/// QeIUTx = 000001b9fbce9c9ebb31070a4a4ac7af54ec9189c1f98948cd24ca0a5029217e4784d3c8692da08a6a512d1c9875d20d8e03664c148fa5d34bbac6d42e499ee5dbf01120
		/// QeIUTy = 000000994a714b6d09afa896dbba9b4f436ab3cdb0d11dcd2aad28b7ba35d6fa6be537b6ffb0f9bf5fe1d594b8f8b8829687c9395c3d938c873f26c7100888c3aca2d59a
		/// OI = a1b2c3d4e54341565369646dbb63a273c81e0aad02f92699bf7baa28fd4509145b0096746894e98e209a85ecb415b8
		/// CAVSTag = 4ade5dc983cc1cf61c90fdbf726fa6a88e9bf411bbaf0015db06ff4348560e4d
		/// Z = 019a19a0a99f60221ee23323b3317292e8c10d57ba04e0b33f6241979ec3895945eed0bdcbc59ab576e7047061f0d63d1aaf78b1d442028605aa1c0f963a3bc9d61a
		/// MacData = 4b435f315f55a1b2c3d4e543415653696401b9fbce9c9ebb31070a4a4ac7af54ec9189c1f98948cd24ca0a5029217e4784d3c8692da08a6a512d1c9875d20d8e03664c148fa5d34bbac6d42e499ee5dbf0112000994a714b6d09afa896dbba9b4f436ab3cdb0d11dcd2aad28b7ba35d6fa6be537b6ffb0f9bf5fe1d594b8f8b8829687c9395c3d938c873f26c7100888c3aca2d59a4214a1a0a1d11679ae22f98d7ae483c1a74008a9cd7f7cf71b1f373a4226f5c58eb621ec56e2537797c01750dcbff07f613b9c58774f9af32aebeadd2226140dc7d56b1aa95c93ab1ec4412e2d0e42cdaac7bf9da3ddbf19fbb1edd0556d9c5a339808905fe8defd8b57ff8f34788192cc0cf7df17d1f351d69ac979a3a495931c287fb8
		/// DKM = 0744e1774149a8b8f88d3a1e20ac1517efd2f54ba4b5f178de99f33b68eea426
		/// Result = P (14 - DKM value should have leading 0 nibble )
		/// </summary>
		public virtual void testMQVwithHMACOnePass()
		{
			AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC", "BC");

			algorithmParameters.init(new ECGenParameterSpec("P-521"));

			ECParameterSpec ecSpec = algorithmParameters.getParameterSpec(typeof(ECParameterSpec));
			KeyFactory keyFact = KeyFactory.getInstance("EC", "BC");

			ECPrivateKey dsCAVS = (ECPrivateKey)keyFact.generatePrivate(new ECPrivateKeySpec(new BigInteger("00000179557decd75b797bea9db656ce99c03a6e0ab13804b5b589644f7db41ceba05c3940c300361061074ca72a828428d9198267fa0b75e1e3e785a0ff20e839414be0", 16), ecSpec));
			ECPublicKey qsCAVS = (ECPublicKey)keyFact.generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger("000001ce7da31681d5f176f3618f205969b9142520363dd26a596866c89988c932e3ce01904d12d1e9b105462e56163dbe7658ba3c472bf1f3c8165813295393ae346764", 16), new BigInteger("000000e70d6e55b76ebd362ff071ab819315593cec650276209a9fdc2c1c48e03c35945f04e74d958cabd3f5e4d1f096a991e807a8f9d217de306a6b561038ca15aea4b9", 16)), ecSpec));

			ECPrivateKey dsIUT = (ECPrivateKey)keyFact.generatePrivate(new ECPrivateKeySpec(new BigInteger("000000c14895dfcc5a6b24994828cfd0a0cc0a881a70173a3eb05c57b098046c8e60a868f6176284aa346eff1fd1b8b879052c5a6d5fd0ae146b35ed7ecee32e294103cd", 16), ecSpec));
			ECPublicKey qsIUT = (ECPublicKey)keyFact.generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger("00000174a658695049db59f6bbe2ad23e1753bf58384a56fc9b3dec13eb873b33e1f4dbd24b6b4ca05a9a11ad531f6d99e9430a774980e8a8d9fd2d1e2a0d76fe3dd36c7", 16), new BigInteger("00000030639849e1df341973db44e7bbba5bb597884a439f9ce54620c3ca73a9804cc26fcda3aaf73ae5a11d5b325cae0e95cfafe1985c6c2fdb892722e7dd2c5d744cf3", 16)), ecSpec));

			ECPrivateKey deIUT = (ECPrivateKey)keyFact.generatePrivate(new ECPrivateKeySpec(new BigInteger("00000138f54e986c7b44f49da389fa9f61bb7265f0cebdeddf09d47c72e55186e2520965fc2c31bb9c0a557e3c28e02a751f097e413c4252c7b0d22452d89f9ac314bc6e", 16), ecSpec));
			ECPublicKey qeIUT = (ECPublicKey)keyFact.generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger("000001b9fbce9c9ebb31070a4a4ac7af54ec9189c1f98948cd24ca0a5029217e4784d3c8692da08a6a512d1c9875d20d8e03664c148fa5d34bbac6d42e499ee5dbf01120", 16), new BigInteger("000000994a714b6d09afa896dbba9b4f436ab3cdb0d11dcd2aad28b7ba35d6fa6be537b6ffb0f9bf5fe1d594b8f8b8829687c9395c3d938c873f26c7100888c3aca2d59a", 16)), ecSpec));

			KeyAgreement uAgree = KeyAgreement.getInstance("ECMQVwithSHA512CKDF", "BC");

			uAgree.init(dsCAVS, new MQVParameterSpec(dsCAVS, qeIUT, Hex.decode("a1b2c3d4e54341565369646dbb63a273c81e0aad02f92699bf7baa28fd4509145b0096746894e98e209a85ecb415b8")));


			KeyAgreement vAgree = KeyAgreement.getInstance("ECMQVwithSHA512CKDF", "BC");
			vAgree.init(dsIUT, new MQVParameterSpec(deIUT, qsCAVS, Hex.decode("a1b2c3d4e54341565369646dbb63a273c81e0aad02f92699bf7baa28fd4509145b0096746894e98e209a85ecb415b8")));

			//
			// agreement
			//
			uAgree.doPhase(qsIUT, true);
			vAgree.doPhase(qsCAVS, true);

			byte[] ux = uAgree.generateSecret(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512.getId()).getEncoded();
			byte[] vx = vAgree.generateSecret(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512.getId()).getEncoded();

			if (!Arrays.areEqual(ux, vx))
			{
				fail("agreement values don't match");
			}

			if (!Arrays.areEqual(Hex.decode("0744e1774149a8b8f88d3a1e20ac1517efd2f54ba4b5f178de99f33b68eea426"), Arrays.copyOfRange(ux, 0, 32)))
			{
				fail("agreement values not correct");
			}
		}

		public virtual BigInteger[] derDecode(byte[] encoding)
		{
			ByteArrayInputStream bIn = new ByteArrayInputStream(encoding);
			ASN1InputStream aIn = new ASN1InputStream(bIn);
			ASN1Sequence s = (ASN1Sequence)aIn.readObject();

			BigInteger[] sig = new BigInteger[2];

			sig[0] = ((ASN1Integer)s.getObjectAt(0)).getValue();
			sig[1] = ((ASN1Integer)s.getObjectAt(1)).getValue();

			return sig;
		}

		public override string getName()
		{
			return "ECDSA5";
		}

		public override void performTest()
		{
			testKeyConversion();
			testAdaptiveKeyConversion();
			decodeTest();
			testECDSA239bitPrime();
			testECDSA239bitBinary();
			testGeneration();
			testKeyPairGenerationWithOIDs();
			testNamedCurveParameterPreservation();
			testNamedCurveSigning();
			testBSI();
			testMQVwithHMACOnePass();
			testAlgorithmParameters();
			testModified();
			testSM2();
			testNonsense();
			testNamedCurveInKeyFactory();
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new ECDSA5Test());
		}
	}

}