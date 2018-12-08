namespace org.bouncycastle.crypto.test
{
	using MD5Digest = org.bouncycastle.crypto.digests.MD5Digest;

	/// <summary>
	/// standard vector test for MD5 from "Handbook of Applied Cryptography", page 345.
	/// </summary>
	public class MD5DigestTest : DigestTest
	{
		internal static readonly string[] messages = new string[] {"", "a", "abc", "abcdefghijklmnopqrstuvwxyz"};

		internal static readonly string[] digests = new string[] {"d41d8cd98f00b204e9800998ecf8427e", "0cc175b9c0f1b6a831c399e269772661", "900150983cd24fb0d6963f7d28e17f72", "c3fcd3d76192e4007dfb496cca67e13b"};

		public MD5DigestTest() : base(new MD5Digest(), messages, digests)
		{
		}

		public override Digest cloneDigest(Digest digest)
		{
			return new MD5Digest((MD5Digest)digest);
		}

		public override Digest cloneDigest(byte[] encodedState)
		{
			return new MD5Digest(encodedState);
		}

		public static void Main(string[] args)
		{
			runTest(new MD5DigestTest());
		}
	}

}