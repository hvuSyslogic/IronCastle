namespace org.bouncycastle.crypto.test
{
	using MD4Digest = org.bouncycastle.crypto.digests.MD4Digest;

	/// <summary>
	/// standard vector test for MD4 from RFC 1320.
	/// </summary>
	public class MD4DigestTest : DigestTest
	{
		private static string[] messages = new string[] {"", "a", "abc", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"};

		private static string[] digests = new string[] {"31d6cfe0d16ae931b73c59d7e0c089c0", "bde52cb31de33e46245e05fbdbd6fb24", "a448017aaf21d8525fc10ae87aa6729d", "e33b4ddc9c38f2199c3e7b164fcc0536"};

		public MD4DigestTest() : base(new MD4Digest(), messages, digests)
		{
		}

		public override Digest cloneDigest(Digest digest)
		{
			return new MD4Digest((MD4Digest)digest);
		}

		public static void Main(string[] args)
		{
			runTest(new MD4DigestTest());
		}
	}

}