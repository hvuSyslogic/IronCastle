namespace org.bouncycastle.crypto.test
{
	using SHA512tDigest = org.bouncycastle.crypto.digests.SHA512tDigest;

	/// <summary>
	/// standard vector test for SHA-512/224 from FIPS 180-4.
	/// 
	/// Note, only the last 2 message entries are FIPS originated..
	/// </summary>
	public class SHA512t224DigestTest : DigestTest
	{
		private static string[] messages = new string[] {"", "a", "abc", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};

		private static string[] digests = new string[] {"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4", "d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327", "4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA", "23FEC5BB94D60B23308192640B0C453335D664734FE40E7268674AF9"};

		// 1 million 'a'
		private static string million_a_digest = "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287";

		public SHA512t224DigestTest() : base(new SHA512tDigest(224), messages, digests)
		{
		}

		public override void performTest()
		{
			base.performTest();

			millionATest(million_a_digest);
		}

		public override Digest cloneDigest(Digest digest)
		{
			return new SHA512tDigest((SHA512tDigest)digest);
		}

		public override Digest cloneDigest(byte[] encodedState)
		{
			return new SHA512tDigest(encodedState);
		}

		public static void Main(string[] args)
		{
			runTest(new SHA512t224DigestTest());
		}
	}

}