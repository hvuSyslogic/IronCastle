namespace org.bouncycastle.crypto.test
{
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;

	/// <summary>
	/// standard vector test for SHA-1 from "Handbook of Applied Cryptography", page 345.
	/// </summary>
	public class SHA1DigestTest : DigestTest
	{
		private static string[] messages = new string[] {"", "a", "abc", "abcdefghijklmnopqrstuvwxyz"};

		private static string[] digests = new string[] {"da39a3ee5e6b4b0d3255bfef95601890afd80709", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "a9993e364706816aba3e25717850c26c9cd0d89d", "32d10c7b8cf96570ca04ce37f2a19d84240d3a89"};

		public SHA1DigestTest() : base(new SHA1Digest(), messages, digests)
		{
		}

		public override Digest cloneDigest(Digest digest)
		{
			return new SHA1Digest((SHA1Digest)digest);
		}

		public override Digest cloneDigest(byte[] encodedState)
		{
			return new SHA1Digest(encodedState);
		}

		public static void Main(string[] args)
		{
			runTest(new SHA1DigestTest());
		}
	}

}