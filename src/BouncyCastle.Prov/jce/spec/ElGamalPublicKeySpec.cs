namespace org.bouncycastle.jce.spec
{

	/// <summary>
	/// This class specifies an ElGamal public key with its associated parameters.
	/// </summary>
	/// <seealso cref= ElGamalPrivateKeySpec </seealso>
	public class ElGamalPublicKeySpec : ElGamalKeySpec
	{
		private BigInteger y;

		public ElGamalPublicKeySpec(BigInteger y, ElGamalParameterSpec spec) : base(spec)
		{

			this.y = y;
		}

		/// <summary>
		/// Returns the public value <code>y</code>.
		/// </summary>
		/// <returns> the public value <code>y</code> </returns>
		public virtual BigInteger getY()
		{
			return y;
		}
	}

}