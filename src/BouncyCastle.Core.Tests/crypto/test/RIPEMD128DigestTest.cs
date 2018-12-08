namespace org.bouncycastle.crypto.test
{
	using RIPEMD128Digest = org.bouncycastle.crypto.digests.RIPEMD128Digest;

	/// <summary>
	/// RIPEMD128 Digest Test
	/// </summary>
	public class RIPEMD128DigestTest : DigestTest
	{
		internal static readonly string[] messages = new string[] {"", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"};

		internal static readonly string[] digests = new string[] {"cdf26213a150dc3ecb610f18f6b38b46", "86be7afa339d0fc7cfc785e72f578d33", "c14a12199c66e4ba84636b0f69144c77", "9e327b3d6e523062afc1132d7df9d1b8", "fd2aa607f71dc8f510714922b371834e", "a1aa0689d0fafa2ddc22e88b49133a06", "d1e959eb179c911faea4624c60c5c702", "3f45ef194732c2dbb2c4a2c769795fa3"};

		internal const string million_a_digest = "4a7f5723f954eba1216c9d8f6320431f";

		public RIPEMD128DigestTest() : base(new RIPEMD128Digest(), messages, digests)
		{
		}

		public override void performTest()
		{
			base.performTest();

			millionATest(million_a_digest);
		}

		public override Digest cloneDigest(Digest digest)
		{
			return new RIPEMD128Digest((RIPEMD128Digest)digest);
		}

		public static void Main(string[] args)
		{
			runTest(new RIPEMD128DigestTest());
		}
	}

}