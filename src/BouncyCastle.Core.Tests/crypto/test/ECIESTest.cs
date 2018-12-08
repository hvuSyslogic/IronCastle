using org.bouncycastle.math.ec;

namespace org.bouncycastle.crypto.test
{

	using ECDHBasicAgreement = org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using IESEngine = org.bouncycastle.crypto.engines.IESEngine;
	using TwofishEngine = org.bouncycastle.crypto.engines.TwofishEngine;
	using ECKeyPairGenerator = org.bouncycastle.crypto.generators.ECKeyPairGenerator;
	using EphemeralKeyPairGenerator = org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
	using KDF2BytesGenerator = org.bouncycastle.crypto.generators.KDF2BytesGenerator;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using PaddedBufferedBlockCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECKeyGenerationParameters = org.bouncycastle.crypto.@params.ECKeyGenerationParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using IESParameters = org.bouncycastle.crypto.@params.IESParameters;
	using IESWithCipherParameters = org.bouncycastle.crypto.@params.IESWithCipherParameters;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using ECIESPublicKeyParser = org.bouncycastle.crypto.parsers.ECIESPublicKeyParser;
	using ECConstants = org.bouncycastle.math.ec.ECConstants;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// test for ECIES - Elliptic Curve Integrated Encryption Scheme
	/// </summary>
	public class ECIESTest : SimpleTest
	{
		private static byte[] TWOFISH_IV = Hex.decode("000102030405060708090a0b0c0d0e0f");

		public ECIESTest()
		{
		}

		public override string getName()
		{
			return "ECIES";
		}

		private void doStaticTest(byte[] iv)
		{
			BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

			ECCurve.Fp curve = new ECCurve.Fp(new BigInteger("6277101735386680763835789423207666416083908700390324961279"), new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), n, ECConstants_Fields.ONE);

			ECDomainParameters @params = new ECDomainParameters(curve, curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), n);

			ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(new BigInteger("651056770906015076056810763456358567190100156695615665659"), @params);

			ECPublicKeyParameters pubKey = new ECPublicKeyParameters(curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), @params);

			AsymmetricCipherKeyPair p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
			AsymmetricCipherKeyPair p2 = new AsymmetricCipherKeyPair(pubKey, priKey);

			//
			// stream test
			//
			IESEngine i1 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()));
			IESEngine i2 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()));
			byte[] d = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
			byte[] e = new byte[] {8, 7, 6, 5, 4, 3, 2, 1};
			CipherParameters p = new IESParameters(d, e, 64);

			i1.init(true, p1.getPrivate(), p2.getPublic(), p);
			i2.init(false, p2.getPrivate(), p1.getPublic(), p);

			byte[] message = Hex.decode("1234567890abcdef");

			byte[] out1 = i1.processBlock(message, 0, message.Length);

			if (!areEqual(out1, Hex.decode("468d89877e8238802403ec4cb6b329faeccfa6f3a730f2cdb3c0a8e8")))
			{
				fail("stream cipher test failed on enc");
			}

			byte[] out2 = i2.processBlock(out1, 0, out1.Length);

			if (!areEqual(out2, message))
			{
				fail("stream cipher test failed");
			}

			//
			// twofish with CBC
			//
			BufferedBlockCipher c1 = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));
			BufferedBlockCipher c2 = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));
			i1 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()), c1);
			i2 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()), c2);
			d = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
			e = new byte[] {8, 7, 6, 5, 4, 3, 2, 1};
			p = new IESWithCipherParameters(d, e, 64, 128);

			if (iv != null)
			{
				p = new ParametersWithIV(p, iv);
			}

			i1.init(true, p1.getPrivate(), p2.getPublic(), p);
			i2.init(false, p2.getPrivate(), p1.getPublic(), p);

			message = Hex.decode("1234567890abcdef");

			out1 = i1.processBlock(message, 0, message.Length);

			if (!areEqual(out1, (iv == null) ? Hex.decode("b8a06ea5c2b9df28b58a0a90a734cde8c9c02903e5c220021fe4417410d1e53a32a71696") : Hex.decode("f246b0e26a2711992cac9c590d08e45c5e730b7c0f4218bb064e27b7dd7c8a3bd8bf01c3")))
			{
				fail("twofish cipher test failed on enc");
			}

			out2 = i2.processBlock(out1, 0, out1.Length);

			if (!areEqual(out2, message))
			{
				fail("twofish cipher test failed");
			}
		}

		private void doShortTest(byte[] iv)
		{
			BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

			ECCurve.Fp curve = new ECCurve.Fp(new BigInteger("6277101735386680763835789423207666416083908700390324961279"), new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), n, ECConstants_Fields.ONE);

			ECDomainParameters @params = new ECDomainParameters(curve, curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), n);

			ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(new BigInteger("651056770906015076056810763456358567190100156695615665659"), @params);

			ECPublicKeyParameters pubKey = new ECPublicKeyParameters(curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), @params);

			AsymmetricCipherKeyPair p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
			AsymmetricCipherKeyPair p2 = new AsymmetricCipherKeyPair(pubKey, priKey);

			//
			// stream test - V 0
			//
			IESEngine i1 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()));
			IESEngine i2 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()));
			byte[] d = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
			byte[] e = new byte[] {8, 7, 6, 5, 4, 3, 2, 1};
			CipherParameters p = new IESParameters(d, e, 64);

			i1.init(true, p1.getPrivate(), p2.getPublic(), p);
			i2.init(false, p2.getPrivate(), p1.getPublic(), p);

			byte[] message = new byte[0];

			byte[] out1 = i1.processBlock(message, 0, message.Length);

			byte[] out2 = i2.processBlock(out1, 0, out1.Length);

			if (!areEqual(out2, message))
			{
				fail("stream cipher test failed");
			}

			try
			{
				i2.processBlock(out1, 0, out1.Length - 1);
				fail("no exception");
			}
			catch (InvalidCipherTextException ex)
			{
				if (!"Length of input must be greater than the MAC and V combined".Equals(ex.Message))
				{
					fail("wrong exception");
				}
			}

			// with ephemeral key pair

			// Generate the ephemeral key pair
			ECKeyPairGenerator gen = new ECKeyPairGenerator();
			gen.init(new ECKeyGenerationParameters(@params, new SecureRandom()));

			EphemeralKeyPairGenerator ephKeyGen = new EphemeralKeyPairGenerator(gen, new KeyEncoderAnonymousInnerClass(this));

			i1.init(p2.getPublic(), p, ephKeyGen);
			i2.init(p2.getPrivate(), p, new ECIESPublicKeyParser(@params));

			out1 = i1.processBlock(message, 0, message.Length);

			out2 = i2.processBlock(out1, 0, out1.Length);

			if (!areEqual(out2, message))
			{
				fail("V cipher test failed");
			}

			try
			{
				i2.processBlock(out1, 0, out1.Length - 1);
				fail("no exception");
			}
			catch (InvalidCipherTextException ex)
			{
				if (!"Length of input must be greater than the MAC and V combined".Equals(ex.Message))
				{
					fail("wrong exception");
				}
			}
		}

		public class KeyEncoderAnonymousInnerClass : KeyEncoder
		{
			private readonly ECIESTest outerInstance;

			public KeyEncoderAnonymousInnerClass(ECIESTest outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public byte[] getEncoded(AsymmetricKeyParameter keyParameter)
			{
				return ((ECPublicKeyParameters)keyParameter).getQ().getEncoded(false);
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: private void doEphemeralTest(byte[] iv, final boolean usePointCompression) throws Exception
		private void doEphemeralTest(byte[] iv, bool usePointCompression)
		{
			BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

			ECCurve.Fp curve = new ECCurve.Fp(new BigInteger("6277101735386680763835789423207666416083908700390324961279"), new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), n, ECConstants_Fields.ONE);

			ECDomainParameters @params = new ECDomainParameters(curve, curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), n);

			ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(new BigInteger("651056770906015076056810763456358567190100156695615665659"), @params);

			ECPublicKeyParameters pubKey = new ECPublicKeyParameters(curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), @params);

			AsymmetricCipherKeyPair p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
			AsymmetricCipherKeyPair p2 = new AsymmetricCipherKeyPair(pubKey, priKey);

			// Generate the ephemeral key pair
			ECKeyPairGenerator gen = new ECKeyPairGenerator();
			gen.init(new ECKeyGenerationParameters(@params, new SecureRandom()));

			EphemeralKeyPairGenerator ephKeyGen = new EphemeralKeyPairGenerator(gen, new KeyEncoderAnonymousInnerClass2(this, usePointCompression));

			//
			// stream test
			//
			IESEngine i1 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()));
			IESEngine i2 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()));

			byte[] d = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
			byte[] e = new byte[] {8, 7, 6, 5, 4, 3, 2, 1};
			CipherParameters p = new IESParameters(d, e, 64);

			i1.init(p2.getPublic(), p, ephKeyGen);
			i2.init(p2.getPrivate(), p, new ECIESPublicKeyParser(@params));

			byte[] message = Hex.decode("1234567890abcdef");

			byte[] out1 = i1.processBlock(message, 0, message.Length);

			byte[] out2 = i2.processBlock(out1, 0, out1.Length);

			if (!areEqual(out2, message))
			{
				fail("stream cipher test failed");
			}

			//
			// twofish with CBC
			//
			BufferedBlockCipher c1 = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));
			BufferedBlockCipher c2 = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));
			i1 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()), c1);
			i2 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()), c2);
			d = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
			e = new byte[] {8, 7, 6, 5, 4, 3, 2, 1};
			p = new IESWithCipherParameters(d, e, 64, 128);

			if (iv != null)
			{
				p = new ParametersWithIV(p, iv);
			}

			i1.init(p2.getPublic(), p, ephKeyGen);
			i2.init(p2.getPrivate(), p, new ECIESPublicKeyParser(@params));

			message = Hex.decode("1234567890abcdef");

			out1 = i1.processBlock(message, 0, message.Length);

			out2 = i2.processBlock(out1, 0, out1.Length);

			if (!areEqual(out2, message))
			{
				fail("twofish cipher test failed");
			}
		}

		public class KeyEncoderAnonymousInnerClass2 : KeyEncoder
		{
			private readonly ECIESTest outerInstance;

			private bool usePointCompression;

			public KeyEncoderAnonymousInnerClass2(ECIESTest outerInstance, bool usePointCompression)
			{
				this.outerInstance = outerInstance;
				this.usePointCompression = usePointCompression;
			}

			public byte[] getEncoded(AsymmetricKeyParameter keyParameter)
			{
				return ((ECPublicKeyParameters)keyParameter).getQ().getEncoded(usePointCompression);
			}
		}

		private void doTest(AsymmetricCipherKeyPair p1, AsymmetricCipherKeyPair p2)
		{
			//
			// stream test
			//
			IESEngine i1 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()));
			IESEngine i2 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()));
			byte[] d = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
			byte[] e = new byte[] {8, 7, 6, 5, 4, 3, 2, 1};
			IESParameters p = new IESParameters(d, e, 64);

			i1.init(true, p1.getPrivate(), p2.getPublic(), p);
			i2.init(false, p2.getPrivate(), p1.getPublic(), p);

			byte[] message = Hex.decode("1234567890abcdef");

			byte[] out1 = i1.processBlock(message, 0, message.Length);

			byte[] out2 = i2.processBlock(out1, 0, out1.Length);

			if (!areEqual(out2, message))
			{
				fail("stream cipher test failed");
			}

			//
			// twofish with CBC
			//
			BufferedBlockCipher c1 = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));
			BufferedBlockCipher c2 = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));
			i1 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()), c1);
			i2 = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()), c2);
			d = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
			e = new byte[] {8, 7, 6, 5, 4, 3, 2, 1};
			p = new IESWithCipherParameters(d, e, 64, 128);

			i1.init(true, p1.getPrivate(), p2.getPublic(), p);
			i2.init(false, p2.getPrivate(), p1.getPublic(), p);

			message = Hex.decode("1234567890abcdef");

			out1 = i1.processBlock(message, 0, message.Length);

			out2 = i2.processBlock(out1, 0, out1.Length);

			if (!areEqual(out2, message))
			{
				fail("twofish cipher test failed");
			}
		}

		public override void performTest()
		{
			doStaticTest(null);
			doStaticTest(TWOFISH_IV);
			doShortTest(null);

			BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

			ECCurve.Fp curve = new ECCurve.Fp(new BigInteger("6277101735386680763835789423207666416083908700390324961279"), new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), n, ECConstants_Fields.ONE);

			ECDomainParameters @params = new ECDomainParameters(curve, curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), n);

			ECKeyPairGenerator eGen = new ECKeyPairGenerator();
			KeyGenerationParameters gParam = new ECKeyGenerationParameters(@params, new SecureRandom());

			eGen.init(gParam);

			AsymmetricCipherKeyPair p1 = eGen.generateKeyPair();
			AsymmetricCipherKeyPair p2 = eGen.generateKeyPair();

			doTest(p1, p2);

			doEphemeralTest(null, false);
			doEphemeralTest(null, true);
			doEphemeralTest(TWOFISH_IV, false);
			doEphemeralTest(TWOFISH_IV, true);
		}

		public static void Main(string[] args)
		{
			runTest(new ECIESTest());
		}
	}

}