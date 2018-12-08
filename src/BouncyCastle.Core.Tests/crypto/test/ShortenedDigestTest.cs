/*
 * Created on 6/05/2006
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
namespace org.bouncycastle.crypto.test
{
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using ShortenedDigest = org.bouncycastle.crypto.digests.ShortenedDigest;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class ShortenedDigestTest : SimpleTest
	{
		public override void performTest()
		{
			ExtendedDigest d = new SHA1Digest();
			ShortenedDigest sd = new ShortenedDigest(new SHA1Digest(), 10);

			if (sd.getDigestSize() != 10)
			{
				fail("size check wrong for SHA-1");
			}

			if (sd.getByteLength() != d.getByteLength())
			{
				fail("byte length check wrong for SHA-1");
			}

			//
			// check output fits
			//
			sd.doFinal(new byte[10], 0);

			d = new SHA512Digest();
			sd = new ShortenedDigest(new SHA512Digest(), 20);

			if (sd.getDigestSize() != 20)
			{
				fail("size check wrong for SHA-512");
			}

			if (sd.getByteLength() != d.getByteLength())
			{
				fail("byte length check wrong for SHA-512");
			}

			//
			// check output fits
			//
			sd.doFinal(new byte[20], 0);

			try
			{
				new ShortenedDigest(null, 20);

				fail("null parameter not caught");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}

			try
			{
				new ShortenedDigest(new SHA1Digest(), 50);

				fail("short digest not caught");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		public override string getName()
		{
			return "ShortenedDigest";
		}

		public static void Main(string[] args)
		{
			runTest(new ShortenedDigestTest());
		}
	}

}