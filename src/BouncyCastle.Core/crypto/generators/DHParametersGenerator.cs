using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.generators
{

	
	public class DHParametersGenerator
	{
		private int size;
		private int certainty;
		private SecureRandom random;

		private static readonly BigInteger TWO = BigInteger.valueOf(2);

		/// <summary>
		/// Initialise the parameters generator.
		/// </summary>
		/// <param name="size"> bit length for the prime p </param>
		/// <param name="certainty"> level of certainty for the prime number tests </param>
		/// <param name="random">  a source of randomness </param>
		public virtual void init(int size, int certainty, SecureRandom random)
		{
			this.size = size;
			this.certainty = certainty;
			this.random = random;
		}

		/// <summary>
		/// which generates the p and g values from the given parameters,
		/// returning the DHParameters object.
		/// <para>
		/// Note: can take a while...
		/// </para>
		/// </summary>
		/// <returns> a generated Diffie-Hellman parameters object. </returns>
		public virtual DHParameters generateParameters()
		{
			//
			// find a safe prime p where p = 2*q + 1, where p and q are prime.
			//
			BigInteger[] safePrimes = DHParametersHelper.generateSafePrimes(size, certainty, random);

			BigInteger p = safePrimes[0];
			BigInteger q = safePrimes[1];
			BigInteger g = DHParametersHelper.selectGenerator(p, q, random);

			return new DHParameters(p, g, q, TWO, null);
		}
	}

}