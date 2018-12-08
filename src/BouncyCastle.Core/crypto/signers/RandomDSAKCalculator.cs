using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.signers
{

	using BigIntegers = org.bouncycastle.util.BigIntegers;

	public class RandomDSAKCalculator : DSAKCalculator
	{
		private static readonly BigInteger ZERO = BigInteger.valueOf(0);

		private BigInteger q;
		private SecureRandom random;

		public virtual bool isDeterministic()
		{
			return false;
		}

		public virtual void init(BigInteger n, SecureRandom random)
		{
			this.q = n;
			this.random = random;
		}

		public virtual void init(BigInteger n, BigInteger d, byte[] message)
		{
			throw new IllegalStateException("Operation not supported");
		}

		public virtual BigInteger nextK()
		{
			int qBitLength = q.bitLength();

			BigInteger k;
			do
			{
				k = BigIntegers.createRandomBigInteger(qBitLength, random);
			} while (k.Equals(ZERO) || k.compareTo(q) >= 0);

			return k;
		}
	}

}