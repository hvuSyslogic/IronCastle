namespace org.bouncycastle.crypto.test
{

	using GOST3411_2012_256Digest = org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
	using GOST3411_2012_512Digest = org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class GOST3411_2012_256DigestTest : DigestTest
	{
		private static readonly string[] messages;

		private static char[] M1 = new char[] {(char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32, (char)0x33, (char)0x34, (char)0x35, (char)0x36, (char)0x37, (char)0x38, (char)0x39, (char)0x30, (char)0x31, (char)0x32};

		private static char[] M2 = new char[] {(char)0xd1, (char)0xe5, (char)0x20, (char)0xe2, (char)0xe5, (char)0xf2, (char)0xf0, (char)0xe8, (char)0x2c, (char)0x20, (char)0xd1, (char)0xf2, (char)0xf0, (char)0xe8, (char)0xe1, (char)0xee, (char)0xe6, (char)0xe8, (char)0x20, (char)0xe2, (char)0xed, (char)0xf3, (char)0xf6, (char)0xe8, (char)0x2c, (char)0x20, (char)0xe2, (char)0xe5, (char)0xfe, (char)0xf2, (char)0xfa, (char)0x20, (char)0xf1, (char)0x20, (char)0xec, (char)0xee, (char)0xf0, (char)0xff, (char)0x20, (char)0xf1, (char)0xf2, (char)0xf0, (char)0xe5, (char)0xeb, (char)0xe0, (char)0xec, (char)0xe8, (char)0x20, (char)0xed, (char)0xe0, (char)0x20, (char)0xf5, (char)0xf0, (char)0xe0, (char)0xe1, (char)0xf0, (char)0xfb, (char)0xff, (char)0x20, (char)0xef, (char)0xeb, (char)0xfa, (char)0xea, (char)0xfb, (char)0x20, (char)0xc8, (char)0xe3, (char)0xee, (char)0xf0, (char)0xe5, (char)0xe2, (char)0xfb};

		static GOST3411_2012_256DigestTest()
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

		private static readonly string[] digests = new string[] {"9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500", "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50"};

		public GOST3411_2012_256DigestTest() : base(new GOST3411_2012_256Digest(), messages, digests)
		{
		}

		public override void performTest()
		{
			base.performTest();

			HMac gMac = new HMac(new GOST3411_2012_256Digest());

			gMac.init(new KeyParameter(Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")));

			byte[] data = Hex.decode("0126bdb87800af214341456563780100");

			gMac.update(data, 0, data.Length);
			byte[] mac = new byte[gMac.getMacSize()];

			gMac.doFinal(mac, 0);

			if (!Arrays.areEqual(Hex.decode("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"), mac))
			{
				fail("mac calculation failed.");
			}
		}

		public override Digest cloneDigest(Digest digest)
		{
			return new GOST3411_2012_256Digest((GOST3411_2012_256Digest)digest);
		}

		public static void Main(string[] args)
		{
			runTest(new GOST3411_2012_256DigestTest());
		}
	}

}