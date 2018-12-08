using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.crypto.test
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using DHKDFParameters = org.bouncycastle.crypto.agreement.kdf.DHKDFParameters;
	using DHKEKGenerator = org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// DHKEK Generator tests - from RFC 2631.
	/// </summary>
	public class DHKEKGeneratorTest : SimpleTest
	{
		private byte[] seed1 = Hex.decode("000102030405060708090a0b0c0d0e0f10111213");
		private ASN1ObjectIdentifier alg1 = PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap;
		private byte[] result1 = Hex.decode("a09661392376f7044d9052a397883246b67f5f1ef63eb5fb");

		private byte[] seed2 = Hex.decode("000102030405060708090a0b0c0d0e0f10111213");
		private ASN1ObjectIdentifier alg2 = PKCSObjectIdentifiers_Fields.id_alg_CMSRC2wrap;
		private byte[] partyAInfo = Hex.decode("0123456789abcdeffedcba9876543201" + "0123456789abcdeffedcba9876543201" + "0123456789abcdeffedcba9876543201" + "0123456789abcdeffedcba9876543201");
		private byte[] result2 = Hex.decode("48950c46e0530075403cce72889604e0");

		public DHKEKGeneratorTest()
		{
		}

		public override void performTest()
		{
			checkMask(1, new DHKEKGenerator(new SHA1Digest()), new DHKDFParameters(alg1, 192, seed1), result1);
			checkMask(2, new DHKEKGenerator(new SHA1Digest()), new DHKDFParameters(alg2, 128, seed2, partyAInfo), result2);
		}

		private void checkMask(int count, DerivationFunction kdf, DerivationParameters @params, byte[] result)
		{
			byte[] data = new byte[result.Length];

			kdf.init(@params);

			kdf.generateBytes(data, 0, data.Length);

			if (!areEqual(result, data))
			{
				fail("DHKEKGenerator failed generator test " + count);
			}
		}

		public override string getName()
		{
			return "DHKEKGenerator";
		}

		public static void Main(string[] args)
		{
			runTest(new DHKEKGeneratorTest());
		}
	}

}