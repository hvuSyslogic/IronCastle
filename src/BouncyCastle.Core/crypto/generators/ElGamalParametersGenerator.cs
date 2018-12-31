using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.generators
{

	
	public class ElGamalParametersGenerator
	{
		private int size;
		private int certainty;
		private SecureRandom random;

		public virtual void init(int size, int certainty, SecureRandom random)
		{
			this.size = size;
			this.certainty = certainty;
			this.random = random;
		}

		/// <summary>
		/// which generates the p and g values from the given parameters,
		/// returning the ElGamalParameters object.
		/// <para>
		/// Note: can take a while...
		/// 
		/// </para>
		/// </summary>
		/// <returns> a generated ElGamal parameters object. </returns>
		public virtual ElGamalParameters generateParameters()
		{
			//
			// find a safe prime p where p = 2*q + 1, where p and q are prime.
			//
			BigInteger[] safePrimes = DHParametersHelper.generateSafePrimes(size, certainty, random);

			BigInteger p = safePrimes[0];
			BigInteger q = safePrimes[1];
			BigInteger g = DHParametersHelper.selectGenerator(p, q, random);

			return new ElGamalParameters(p, g);
		}
	}

}