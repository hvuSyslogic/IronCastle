﻿namespace org.bouncycastle.crypto.test
{
	using SHA384Digest = org.bouncycastle.crypto.digests.SHA384Digest;

	/// <summary>
	/// standard vector test for SHA-384 from FIPS Draft 180-2.
	/// 
	/// Note, the first two vectors are _not_ from the draft, the last three are.
	/// </summary>
	public class SHA384DigestTest : DigestTest
	{
		private static string[] messages = new string[] {"", "a", "abc", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};

		private static string[] digests = new string[] {"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"};

		private static string million_a_digest = "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985";

		public SHA384DigestTest() : base(new SHA384Digest(), messages, digests)
		{
		}

		public override void performTest()
		{
			base.performTest();

			millionATest(million_a_digest);
		}

		public override Digest cloneDigest(Digest digest)
		{
			return new SHA384Digest((SHA384Digest)digest);
		}

		public override Digest cloneDigest(byte[] encodedState)
		{
			return new SHA384Digest(encodedState);
		}

		public static void Main(string[] args)
		{
			runTest(new SHA384DigestTest());
		}
	}

}