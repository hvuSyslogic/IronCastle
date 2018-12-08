namespace org.bouncycastle.jce.spec
{

	/// <summary>
	/// This class specifies an ElGamal private key with its associated parameters.
	/// </summary>
	/// <seealso cref= ElGamalPublicKeySpec </seealso>
	public class ElGamalPrivateKeySpec : ElGamalKeySpec
	{
		private BigInteger x;

		public ElGamalPrivateKeySpec(BigInteger x, ElGamalParameterSpec spec) : base(spec)
		{

			this.x = x;
		}

		/// <summary>
		/// Returns the private value <code>x</code>.
		/// </summary>
		/// <returns> the private value <code>x</code> </returns>
		public virtual BigInteger getX()
		{
			return x;
		}
	}

}