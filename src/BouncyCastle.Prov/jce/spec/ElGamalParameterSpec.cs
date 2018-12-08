namespace org.bouncycastle.jce.spec
{

	public class ElGamalParameterSpec : AlgorithmParameterSpec
	{
		private BigInteger p;
		private BigInteger g;

		/// <summary>
		/// Constructs a parameter set for Diffie-Hellman, using a prime modulus
		/// <code>p</code> and a base generator <code>g</code>.
		/// </summary>
		/// <param name="p"> the prime modulus </param>
		/// <param name="g"> the base generator </param>
		public ElGamalParameterSpec(BigInteger p, BigInteger g)
		{
			this.p = p;
			this.g = g;
		}

		/// <summary>
		/// Returns the prime modulus <code>p</code>.
		/// </summary>
		/// <returns> the prime modulus <code>p</code> </returns>
		public virtual BigInteger getP()
		{
			return p;
		}

		/// <summary>
		/// Returns the base generator <code>g</code>.
		/// </summary>
		/// <returns> the base generator <code>g</code> </returns>
		public virtual BigInteger getG()
		{
			return g;
		}
	}

}