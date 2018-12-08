namespace org.bouncycastle.crypto.test
{

	using GOST3411Digest = org.bouncycastle.crypto.digests.GOST3411Digest;
	using GOST3411_2012_512Digest = org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
	using PKCS5S1ParametersGenerator = org.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class GOST3411_2012_512DigestTest : DigestTest
	{
		private static readonly string[] messages;

		private static char[] M1 = new char[] {(char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32};

		private static char[] M2 = new char[] {(char)0xd1, (char)0xe5, (char)0x20, (char)0xe2, (char)0xe5, (char)0xf2, (char)0xf0, (char)0xe8, (char)0x2c, (char)0x20, (char)0xd1, (char)0xf2, (char)0xf0, (char)0xe8, (char)0xe1, (char)0xee, (char)0xe6, (char)0xe8, (char)0x20, (char)0xe2, (char)0xed, (char)0xf3, (char)0xf6, (char)0xe8, (char)0x2c, (char)0x20, (char)0xe2, (char)0xe5, (char)0xfe, (char)0xf2, (char)0xfa, (char)0x20, (char)0xf1, (char)0x20, (char)0xec, (char)0xee, (char)0xf0, (char)0xff, (char)0x20, (char)0xf1, (char)0xf2, (char)0xf0, (char)0xe5, (char)0xeb, (char)0xe0, (char)0xec, (char)0xe8, (char)0x20, (char)0xed, (char)0xe0, (char)0x20, (char)0xf5, (char)0xf0, (char)0xe0, (char)0xe1, (char)0xf0, (char)0xfb, (char)0xff, (char)0x20, (char)0xef, (char)0xeb, (char)0xfa, (char)0xea, (char)0xfb, (char)0x20, (char)0xc8, (char)0xe3, (char)0xee, (char)0xf0, (char)0xe5, (char)0xe2, (char)0xfb};

		static GOST3411_2012_512DigestTest()
		{
			ArrayList<string> strList = new ArrayList<string>();

			strList.add(new string(M1));
			strList.add(new string(M2));
			messages = new string[strList.size()];
			for (int i = 0; i < strList.size(); i++)
			{
				messages[i] = (string)strList.get(i);
			}
		}

		private static readonly string[] digests = new string[] {"1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48", "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28"};

		public GOST3411_2012_512DigestTest() : base(new GOST3411_2012_512Digest(), messages, digests)
		{
		}

		public override void performTest()
		{
			base.performTest();

			HMac gMac = new HMac(new GOST3411_2012_512Digest());

			gMac.init(new KeyParameter(Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")));

			byte[] data = Hex.decode("0126bdb87800af214341456563780100");

			gMac.update(data, 0, data.Length);
			byte[] mac = new byte[gMac.getMacSize()];

			gMac.doFinal(mac, 0);

			if (!Arrays.areEqual(Hex.decode("a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"), mac))
			{
				fail("mac calculation failed.");
			}
		}

		public override Digest cloneDigest(Digest digest)
		{
			return new GOST3411_2012_512Digest((GOST3411_2012_512Digest)digest);
		}

		public static void Main(string[] args)
		{
			runTest(new GOST3411_2012_512DigestTest());
		}
	}

}