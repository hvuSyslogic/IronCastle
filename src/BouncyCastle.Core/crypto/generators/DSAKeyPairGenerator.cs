using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.generators
{

						
	/// <summary>
	/// a DSA key pair generator.
	/// 
	/// This generates DSA keys in line with the method described 
	/// in <i>FIPS 186-3 B.1 FFC Key Pair Generation</i>.
	/// </summary>
	public class DSAKeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private DSAKeyGenerationParameters param;

		public virtual void init(KeyGenerationParameters param)
		{
			this.param = (DSAKeyGenerationParameters)param;
		}

		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			DSAParameters dsaParams = param.getParameters();

			BigInteger x = generatePrivateKey(dsaParams.getQ(), param.getRandom());
			BigInteger y = calculatePublicKey(dsaParams.getP(), dsaParams.getG(), x);

			return new AsymmetricCipherKeyPair(new DSAPublicKeyParameters(y, dsaParams), new DSAPrivateKeyParameters(x, dsaParams));
		}

		private static BigInteger generatePrivateKey(BigInteger q, SecureRandom random)
		{
			// B.1.2 Key Pair Generation by Testing Candidates
			int minWeight = (int)((uint)q.bitLength() >> 2);
			for (;;)
			{
				// TODO Prefer this method? (change test cases that used fixed random)
				// B.1.1 Key Pair Generation Using Extra Random Bits
	//            BigInteger x = new BigInteger(q.bitLength() + 64, random).mod(q.subtract(ONE)).add(ONE);

				BigInteger x = BigIntegers.createRandomInRange(ONE, q.subtract(ONE), random);
				if (WNafUtil.getNafWeight(x) >= minWeight)
				{
					return x;
				}
			}
		}

		private static BigInteger calculatePublicKey(BigInteger p, BigInteger g, BigInteger x)
		{
			return g.modPow(x, p);
		}
	}

}