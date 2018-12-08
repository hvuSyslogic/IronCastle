using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec;

namespace org.bouncycastle.crypto.ec
{

	using ECConstants = org.bouncycastle.math.ec.ECConstants;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	public class ECUtil
	{
		internal static BigInteger generateK(BigInteger n, SecureRandom random)
		{
			int nBitLength = n.bitLength();
			BigInteger k;
			do
			{
				k = BigIntegers.createRandomBigInteger(nBitLength, random);
			} while (k.Equals(ECConstants_Fields.ZERO) || (k.compareTo(n) >= 0));
			return k;
		}
	}

}