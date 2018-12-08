namespace org.bouncycastle.jce.provider.test
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using ECPrivateKeySpec = org.bouncycastle.jce.spec.ECPrivateKeySpec;
	using ECPublicKeySpec = org.bouncycastle.jce.spec.ECPublicKeySpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using TestRandomBigInteger = org.bouncycastle.util.test.TestRandomBigInteger;

	public class DSTU4145Test : SimpleTest
	{

		public override string getName()
		{
			return "DSTU4145";
		}

		public override void performTest()
		{

			DSTU4145Test_Renamed();
			generationTest();
			//parametersTest();
			generateFromCurveTest();
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());
			runTest(new DSTU4145Test());
		}

		internal static readonly BigInteger r = new BigInteger("00f2702989366e9569d5092b83ac17f918bf040c487a", 16);
		internal static readonly BigInteger s = new BigInteger("01dd460039db3be70392d7012f2a492d3e59091ab7a6", 16);

		private void generationTest()
		{
			ECCurve.F2m curve = new ECCurve.F2m(173, 1, 2, 10, BigInteger.ZERO, new BigInteger("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", 16));

			ECParameterSpec spec = new ECParameterSpec(curve, curve.createPoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16), false), new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16));

			SecureRandom k = new TestRandomBigInteger(Hex.decode("00137449348C1249971759D99C252FFE1E14D8B31F00"));
			SecureRandom keyRand = new TestRandomBigInteger(Hex.decode("0000955CD7E344303D1034E66933DC21C8044D42ADB8"));

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSTU4145", "BC");
			keyGen.initialize(spec, keyRand);
			KeyPair pair = keyGen.generateKeyPair();

			Signature sgr = Signature.getInstance("DSTU4145", "BC");

			sgr.initSign(pair.getPrivate(), k);

			byte[] message = new byte[]{(byte)'a', (byte)'b', (byte)'c'};

			sgr.update(message);

			byte[] sigBytes = sgr.sign();

			sgr.initVerify(pair.getPublic());

			sgr.update(message);

			if (!sgr.verify(sigBytes))
			{
				fail("DSTU4145 verification failed");
			}

			BigInteger[] sig = decode(sigBytes);

			if (!r.Equals(sig[0]))
			{
				fail(": r component wrong." + Strings.lineSeparator() + " expecting: " + r + Strings.lineSeparator() + " got      : " + sig[0].ToString(16));
			}

			if (!s.Equals(sig[1]))
			{
				fail(": s component wrong." + Strings.lineSeparator() + " expecting: " + s + Strings.lineSeparator() + " got      : " + sig[1].ToString(16));
			}
		}

		private void generateFromCurveTest()
		{
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSTU4145", "BC");

			for (int i = 0; i != 10; i++)
			{
				keyGen.initialize(new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2." + i));
			}

			try
			{
				keyGen.initialize(new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2." + 10));
				fail("no exception");
			}
			catch (InvalidAlgorithmParameterException e)
			{
				isTrue("unknown curve name: 1.2.804.2.1.1.1.1.3.1.1.2.10".Equals(e.Message));
			}
		}

//JAVA TO C# CONVERTER NOTE: Members cannot have the same name as their enclosing type:
		private void DSTU4145Test_Renamed()
		{

			SecureRandom k = new TestRandomBigInteger(Hex.decode("00137449348C1249971759D99C252FFE1E14D8B31F00"));

			ECCurve.F2m curve = new ECCurve.F2m(173, 1, 2, 10, BigInteger.ZERO, new BigInteger("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", 16));

			ECParameterSpec spec = new ECParameterSpec(curve, curve.createPoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16), false), new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16));

			ECPrivateKeySpec priKey = new ECPrivateKeySpec(new BigInteger("955CD7E344303D1034E66933DC21C8044D42ADB8", 16), spec);

			ECPublicKeySpec pubKey = new ECPublicKeySpec(curve.createPoint(new BigInteger("22de541d48a75c1c3b8c7c107b2551c5093c6c096e1", 16), new BigInteger("1e5b602efc0269d61e64d97c9193d2788fa05c4b7fd5", 16), false), spec);

			Signature sgr = Signature.getInstance("DSTU4145", "BC");
			KeyFactory f = KeyFactory.getInstance("DSTU4145", "BC");
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
				fail("DSTU4145 verification failed");
			}

			BigInteger[] sig = decode(sigBytes);

			if (!r.Equals(sig[0]))
			{
				fail(": r component wrong." + Strings.lineSeparator() + " expecting: " + r + Strings.lineSeparator() + " got      : " + sig[0].ToString(16));
			}

			if (!s.Equals(sig[1]))
			{
				fail(": s component wrong." + Strings.lineSeparator() + " expecting: " + s + Strings.lineSeparator() + " got      : " + sig[1].ToString(16));
			}
		}

		private BigInteger[] decode(byte[] encoding)
		{
			ASN1OctetString octetString = (ASN1OctetString)ASN1OctetString.fromByteArray(encoding);
			encoding = octetString.getOctets();

			byte[] r = new byte[encoding.Length / 2];
			byte[] s = new byte[encoding.Length / 2];

			JavaSystem.arraycopy(encoding, 0, s, 0, encoding.Length / 2);

			JavaSystem.arraycopy(encoding, encoding.Length / 2, r, 0, encoding.Length / 2);

			BigInteger[] sig = new BigInteger[2];

			sig[0] = new BigInteger(1, r);
			sig[1] = new BigInteger(1, s);

			return sig;
		}
	}

}