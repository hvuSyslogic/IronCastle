namespace org.bouncycastle.jce.spec
{

	public class ElGamalGenParameterSpec : AlgorithmParameterSpec
	{
		private int primeSize;

		/*
		 * @param primeSize the size (in bits) of the prime modulus.
		 */
		public ElGamalGenParameterSpec(int primeSize)
		{
			this.primeSize = primeSize;
		}

		/// <summary>
		/// Returns the size in bits of the prime modulus.
		/// </summary>
		/// <returns> the size in bits of the prime modulus </returns>
		public virtual int getPrimeSize()
		{
			return primeSize;
		}
	}

}