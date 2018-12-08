using org.bouncycastle.math.ec;

namespace org.bouncycastle.crypto.ec.test
{

	using ECKeyPairGenerator = org.bouncycastle.crypto.generators.ECKeyPairGenerator;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECKeyGenerationParameters = org.bouncycastle.crypto.@params.ECKeyGenerationParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ECConstants = org.bouncycastle.math.ec.ECConstants;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class ECTransformationTest : SimpleTest
	{
		public override string getName()
		{
			return "ECTransformationTest";
		}

		public override void performTest()
		{
			BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

			ECCurve.Fp curve = new ECCurve.Fp(new BigInteger("6277101735386680763835789423207666416083908700390324961279"), new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), n, ECConstants_Fields.ONE);

			ECDomainParameters @params = new ECDomainParameters(curve, curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), n);

			ECPublicKeyParameters pubKey = new ECPublicKeyParameters(curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), @params);

			ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(new BigInteger("651056770906015076056810763456358567190100156695615665659"), @params);


			ParametersWithRandom pRandom = new ParametersWithRandom(pubKey, new SecureRandom());

			doTest(priKey, pRandom, BigInteger.valueOf(20));

			BigInteger rand = new BigInteger(pubKey.getParameters().getN().bitLength() - 1, new SecureRandom());

			doTest(priKey, pRandom, rand);
			doSameKeyTest(priKey, pRandom, rand);
		}

		private void doTest(ECPrivateKeyParameters priKey, ParametersWithRandom pRandom, BigInteger value)
		{
			ECPoint data = priKey.getParameters().getG().multiply(value);

			ECEncryptor encryptor = new ECElGamalEncryptor();

			encryptor.init(pRandom);

			ECPair pair = encryptor.encrypt(data);

			ECKeyPairGenerator ecGen = new ECKeyPairGenerator();

			ecGen.init(new ECKeyGenerationParameters(priKey.getParameters(), new SecureRandom()));

			AsymmetricCipherKeyPair reEncKP = ecGen.generateKeyPair();

			ECPairTransform ecr = new ECNewPublicKeyTransform();

			ecr.init(reEncKP.getPublic());

			ECPair srcPair = pair;

			// re-encrypt the message portion
			pair = ecr.transform(srcPair);

			ECDecryptor decryptor = new ECElGamalDecryptor();

			decryptor.init(priKey);

			// decrypt out the original private key
			ECPoint p = decryptor.decrypt(new ECPair(srcPair.getX(), pair.getY()));

			decryptor.init(reEncKP.getPrivate());

			// decrypt the fully transformed point.
			ECPoint result = decryptor.decrypt(new ECPair(pair.getX(), p));

			if (!data.Equals(result))
			{
				fail("point pair failed to decrypt back to original");
			}
		}

		private void doSameKeyTest(ECPrivateKeyParameters priKey, ParametersWithRandom pRandom, BigInteger value)
		{
			ECPoint data = priKey.getParameters().getG().multiply(value);

			ECEncryptor encryptor = new ECElGamalEncryptor();

			encryptor.init(pRandom);

			ECPair pair = encryptor.encrypt(data);

			ECPairTransform ecr = new ECNewRandomnessTransform();

			ecr.init(pRandom);

			ECPair srcPair = pair;

			// re-encrypt the message portion
			pair = ecr.transform(srcPair);

			ECDecryptor decryptor = new ECElGamalDecryptor();

			decryptor.init(priKey);

			// decrypt the fully transformed point.
			ECPoint result = decryptor.decrypt(pair);

			if (!data.Equals(result))
			{
				fail("point pair failed to decrypt back to original");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new ECTransformationTest());
		}
	}

}