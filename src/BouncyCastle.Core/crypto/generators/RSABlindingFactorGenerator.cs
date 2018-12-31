using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.generators
{

				
	/// <summary>
	/// Generate a random factor suitable for use with RSA blind signatures
	/// as outlined in Chaum's blinding and unblinding as outlined in
	/// "Handbook of Applied Cryptography", page 475.
	/// </summary>
	public class RSABlindingFactorGenerator
	{
		private static BigInteger ZERO = BigInteger.valueOf(0);
		private static BigInteger ONE = BigInteger.valueOf(1);

		private RSAKeyParameters key;
		private SecureRandom random;

		/// <summary>
		/// Initialise the factor generator
		/// </summary>
		/// <param name="param"> the necessary RSA key parameters. </param>
		public virtual void init(CipherParameters param)
		{
			if (param is ParametersWithRandom)
			{
				ParametersWithRandom rParam = (ParametersWithRandom)param;

				key = (RSAKeyParameters)rParam.getParameters();
				random = rParam.getRandom();
			}
			else
			{
				key = (RSAKeyParameters)param;
				random = CryptoServicesRegistrar.getSecureRandom();
			}

			if (key is RSAPrivateCrtKeyParameters)
			{
				throw new IllegalArgumentException("generator requires RSA public key");
			}
		}

		/// <summary>
		/// Generate a suitable blind factor for the public key the generator was initialised with.
		/// </summary>
		/// <returns> a random blind factor </returns>
		public virtual BigInteger generateBlindingFactor()
		{
			if (key == null)
			{
				throw new IllegalStateException("generator not initialised");
			}

			BigInteger m = key.getModulus();
			int length = m.bitLength() - 1; // must be less than m.bitLength()
			BigInteger factor;
			BigInteger gcd;

			do
			{
				factor = BigIntegers.createRandomBigInteger(length, random);
				gcd = factor.gcd(m);
			} while (factor.Equals(ZERO) || factor.Equals(ONE) || !gcd.Equals(ONE));

			return factor;
		}
	}

}