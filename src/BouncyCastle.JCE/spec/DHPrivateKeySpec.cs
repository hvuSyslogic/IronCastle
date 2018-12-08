namespace javax.crypto.spec
{

	/// <summary>
	/// This class specifies a Diffie-Hellman private key with its associated parameters.
	/// </summary>
	/// <seealso cref= DHPublicKeySpec </seealso>
	public class DHPrivateKeySpec : KeySpec
	{
		private BigInteger x;
		private BigInteger p;
		private BigInteger g;

		/// <summary>
		/// Constructor that takes a private value <code>x</code>, a prime
		/// modulus <code>p</code>, and a base generator <code>g</code>.
		/// </summary>
		public DHPrivateKeySpec(BigInteger x, BigInteger p, BigInteger g)
		{
			this.x = x;
			this.p = p;
			this.g = g;
		}

		/// <summary>
		/// Returns the private value <code>x</code>.
		/// </summary>
		/// <returns> the private value <code>x</code> </returns>
		public virtual BigInteger getX()
		{
			return x;
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