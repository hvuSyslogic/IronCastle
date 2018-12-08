using org.bouncycastle.asn1.sec;

namespace org.bouncycastle.jce.provider.test
{

	using SECObjectIdentifiers = org.bouncycastle.asn1.sec.SECObjectIdentifiers;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class AlgorithmParametersTest : SimpleTest
	{
		private byte[] dsaParams = Base64.decode("MIGcAkEAjfKklEkidqo9JXWbsGhpy+rA2Dr7jQz3y7gyTw14guXQdi/FtyEOr8Lprawyq3qsSWk9+/g3J" + "MLsBzbuMcgCkQIVAMdzIYxzfsjumTtPLe0w9I7azpFfAkBP3Z9K7oNeZMXEXYpqvrMUgVdFjq4lnWJoV8" + "Rwe+TERStHTkqSO7sp0lq7EEggVMcuXtarKNsxaJ+qyYv/n1t6");

		private void basicTest(string algorithm, Class algorithmParameterSpec, byte[] asn1Encoded)
		{
			AlgorithmParameters alg = AlgorithmParameters.getInstance(algorithm, "BC");

			alg.init(asn1Encoded);

			try
			{
				alg.init(asn1Encoded);
				fail("encoded re-initialization not detected");
			}
			catch (IOException)
			{
				// expected already initialized
			}

			AlgorithmParameterSpec spec = alg.getParameterSpec(algorithmParameterSpec);

			try
			{
				alg.init(spec);
				fail("spec re-initialization not detected");
			}
			catch (InvalidParameterSpecException)
			{
				// expected already initialized
			}

			// check default
			spec = alg.getParameterSpec(typeof(AlgorithmParameterSpec));

			try
			{
				spec = alg.getParameterSpec(typeof(IvParameterSpec));
				fail("wrong spec not detected");
			}
			catch (InvalidParameterSpecException)
			{
				// expected unknown object
			}

			try
			{
				spec = alg.getParameterSpec(null);
				fail("null spec not detected");
			}
			catch (NullPointerException)
			{
				// expected unknown object
			}

			alg = AlgorithmParameters.getInstance(algorithm, "BC");

			alg.init(asn1Encoded, "ASN.1");

			alg = AlgorithmParameters.getInstance(algorithm, "BC");

			alg.init(asn1Encoded, null);

			alg = AlgorithmParameters.getInstance(algorithm, "BC");

			try
			{
				alg.init(asn1Encoded, "FRED");
				fail("unknown spec not detected");
			}
			catch (IOException)
			{
				// expected already initialized
			}
		}

		public override void performTest()
		{
			basicTest("DSA", typeof(DSAParameterSpec), dsaParams);

			AlgorithmParameters al = AlgorithmParameters.getInstance("EC", "BC");

			al.init(new ECGenParameterSpec(SECObjectIdentifiers_Fields.secp256r1.getId()));

			if (!Arrays.areEqual(Hex.decode("06082a8648ce3d030107"), al.getEncoded()))
			{
				 fail("EC param test failed");
			}
		}

		public override string getName()
		{
			return "AlgorithmParameters";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new AlgorithmParametersTest());
		}
	}

}