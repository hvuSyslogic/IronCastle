using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.mceliece
{
	using Digest = org.bouncycastle.crypto.Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using SHA224Digest = org.bouncycastle.crypto.digests.SHA224Digest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA384Digest = org.bouncycastle.crypto.digests.SHA384Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;

	public class Utils
	{
		internal static Digest getDigest(string digestName)
		{
			if (digestName.Equals("SHA-1"))
			{
				return new SHA1Digest();
			}
			if (digestName.Equals("SHA-224"))
			{
				return new SHA224Digest();
			}
			if (digestName.Equals("SHA-256"))
			{
				return new SHA256Digest();
			}
			if (digestName.Equals("SHA-384"))
			{
				return new SHA384Digest();
			}
			if (digestName.Equals("SHA-512"))
			{
				return new SHA512Digest();
			}

			throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
		}
	}

}