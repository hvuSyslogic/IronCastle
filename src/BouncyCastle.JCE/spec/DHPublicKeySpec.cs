namespace javax.crypto.spec
{

	/// <summary>
	/// This class specifies a Diffie-Hellman public key with its associated parameters.
	/// </summary>
	/// <seealso cref= DHPrivateKeySpec </seealso>
	public class DHPublicKeySpec : KeySpec
	{
		private BigInteger y;
		private BigInteger p;
		private BigInteger g;

		/// <summary>
		/// Constructor that takes a public value <code>y</code>, a prime
		/// modulus <code>p</code>, and a base generator <code>g</code>.
		/// </summary>
		public DHPublicKeySpec(BigInteger y, BigInteger p, BigInteger g)
		{
			this.y = y;
			this.p = p;
			this.g = g;
		}

		/// <summary>
		/// Returns the public value <code>y</code>.
		/// </summary>
		/// <returns> the public value <code>y</code> </returns>
		public virtual BigInteger getY()
		{
			return y;
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