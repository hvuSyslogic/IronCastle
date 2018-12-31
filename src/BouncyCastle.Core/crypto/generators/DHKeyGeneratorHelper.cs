using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.generators
{

			
	public class DHKeyGeneratorHelper
	{
		internal static readonly DHKeyGeneratorHelper INSTANCE = new DHKeyGeneratorHelper();

		private static readonly BigInteger ONE = BigInteger.valueOf(1);
		private static readonly BigInteger TWO = BigInteger.valueOf(2);

		private DHKeyGeneratorHelper()
		{
		}

		public virtual BigInteger calculatePrivate(DHParameters dhParams, SecureRandom random)
		{
			int limit = dhParams.getL();

			if (limit != 0)
			{
			    {int minWeight = (int)((uint)limit >> 2);
				for (;;)
				{
					BigInteger x = BigIntegers.createRandomBigInteger(limit, random).setBit(limit - 1);
					if (WNafUtil.getNafWeight(x) >= minWeight)
					{
						return x;
					}
				}
			    }
            }

			BigInteger min = TWO;
			int m = dhParams.getM();
			if (m != 0)
			{
				min = ONE.shiftLeft(m - 1);
			}

			BigInteger q = dhParams.getQ();
			if (q == null)
			{
				q = dhParams.getP();
			}
			BigInteger max = q.subtract(TWO);

		    {int minWeight = (int)((uint)max.bitLength() >> 2);
			for (;;)
			{
				BigInteger x = BigIntegers.createRandomInRange(min, max, random);
				if (WNafUtil.getNafWeight(x) >= minWeight)
				{
					return x;
				}
			}
            }
		}

		public virtual BigInteger calculatePublic(DHParameters dhParams, BigInteger x)
		{
			return dhParams.getG().modPow(x, dhParams.getP());
		}
	}

}