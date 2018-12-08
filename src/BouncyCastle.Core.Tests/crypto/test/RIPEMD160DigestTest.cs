﻿namespace org.bouncycastle.crypto.test
{
	using RIPEMD160Digest = org.bouncycastle.crypto.digests.RIPEMD160Digest;

	/// <summary>
	/// RIPEMD160 Digest Test
	/// </summary>
	public class RIPEMD160DigestTest : DigestTest
	{
		internal static readonly string[] messages = new string[] {"", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"};

		internal static readonly string[] digests = new string[] {"9c1185a5c5e9fc54612808977ee8f548b2258d31", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "5d0689ef49d2fae572b881b123a85ffa21595f36", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc", "12a053384a9c0c88e405a06c27dcf49ada62eb2b", "b0e20b6e3116640286ed3a87a5713079b21f5189", "9b752e45573d4b39f4dbd3323cab82bf63326bfb"};

		internal const string million_a_digest = "52783243c1697bdbe16d37f97f68f08325dc1528";

		public RIPEMD160DigestTest() : base(new RIPEMD160Digest(), messages, digests)
		{
		}

		public override void performTest()
		{
			base.performTest();

			millionATest(million_a_digest);
		}

		public override Digest cloneDigest(Digest digest)
		{
			return new RIPEMD160Digest((RIPEMD160Digest)digest);
		}

		public static void Main(string[] args)
		{
			runTest(new RIPEMD160DigestTest());
		}
	}

}