using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class DSAParameterGenerationParameters
	{
		public const int DIGITAL_SIGNATURE_USAGE = 1;
		public const int KEY_ESTABLISHMENT_USAGE = 2;

		private readonly int l;
		private readonly int n;
		private readonly int usageIndex;
		private readonly int certainty;
		private readonly SecureRandom random;

		/// <summary>
		/// Construct without a usage index, this will do a random construction of G.
		/// </summary>
		/// <param name="L"> desired length of prime P in bits (the effective key size). </param>
		/// <param name="N"> desired length of prime Q in bits. </param>
		/// <param name="certainty"> certainty level for prime number generation. </param>
		/// <param name="random"> the source of randomness to use. </param>
		public DSAParameterGenerationParameters(int L, int N, int certainty, SecureRandom random) : this(L, N, certainty, random, -1)
		{
		}

		/// <summary>
		/// Construct for a specific usage index - this has the effect of using verifiable canonical generation of G.
		/// </summary>
		/// <param name="L"> desired length of prime P in bits (the effective key size). </param>
		/// <param name="N"> desired length of prime Q in bits. </param>
		/// <param name="certainty"> certainty level for prime number generation. </param>
		/// <param name="random"> the source of randomness to use. </param>
		/// <param name="usageIndex"> a valid usage index. </param>
		public DSAParameterGenerationParameters(int L, int N, int certainty, SecureRandom random, int usageIndex)
		{
			this.l = L;
			this.n = N;
			this.certainty = certainty;
			this.usageIndex = usageIndex;
			this.random = random;
		}

		public virtual int getL()
		{
			return l;
		}

		public virtual int getN()
		{
			return n;
		}

		public virtual int getCertainty()
		{
			return certainty;
		}

		public virtual SecureRandom getRandom()
		{
			return random;
		}

		public virtual int getUsageIndex()
		{
			return usageIndex;
		}
	}

}