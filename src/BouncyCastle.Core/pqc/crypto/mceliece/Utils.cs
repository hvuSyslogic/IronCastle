using org.bouncycastle.crypto;
using org.bouncycastle.crypto.digests;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.mceliece
{
						
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