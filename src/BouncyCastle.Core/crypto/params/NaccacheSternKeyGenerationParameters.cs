using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// Parameters for NaccacheStern public private key generation. For details on
	/// this cipher, please see
	/// 
	/// http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
	/// </summary>
	public class NaccacheSternKeyGenerationParameters : KeyGenerationParameters
	{

		// private BigInteger publicExponent;
		private int certainty;

		private int cntSmallPrimes;

		private bool debug = false;

		/// <summary>
		/// Parameters for generating a NaccacheStern KeyPair.
		/// </summary>
		/// <param name="random">
		///            The source of randomness </param>
		/// <param name="strength">
		///            The desired strength of the Key in Bits </param>
		/// <param name="certainty">
		///            the probability that the generated primes are not really prime
		///            as integer: 2^(-certainty) is then the probability </param>
		/// <param name="cntSmallPrimes">
		///            How many small key factors are desired </param>
		public NaccacheSternKeyGenerationParameters(SecureRandom random, int strength, int certainty, int cntSmallPrimes) : this(random, strength, certainty, cntSmallPrimes, false)
		{
		}

		/// <summary>
		/// Parameters for a NaccacheStern KeyPair.
		/// </summary>
		/// <param name="random">
		///            The source of randomness </param>
		/// <param name="strength">
		///            The desired strength of the Key in Bits </param>
		/// <param name="certainty">
		///            the probability that the generated primes are not really prime
		///            as integer: 2^(-certainty) is then the probability </param>
		/// <param name="cntSmallPrimes">
		///            How many small key factors are desired </param>
		/// <param name="debug">
		///            Turn debugging on or off (reveals secret information, use with
		///            caution) </param>
		public NaccacheSternKeyGenerationParameters(SecureRandom random, int strength, int certainty, int cntSmallPrimes, bool debug) : base(random, strength)
		{

			this.certainty = certainty;
			if (cntSmallPrimes % 2 == 1)
			{
				throw new IllegalArgumentException("cntSmallPrimes must be a multiple of 2");
			}
			if (cntSmallPrimes < 30)
			{
				throw new IllegalArgumentException("cntSmallPrimes must be >= 30 for security reasons");
			}
			this.cntSmallPrimes = cntSmallPrimes;

			this.debug = debug;
		}

		/// <returns> Returns the certainty. </returns>
		public virtual int getCertainty()
		{
			return certainty;
		}

		/// <returns> Returns the cntSmallPrimes. </returns>
		public virtual int getCntSmallPrimes()
		{
			return cntSmallPrimes;
		}

		public virtual bool isDebug()
		{
			return debug;
		}

	}

}