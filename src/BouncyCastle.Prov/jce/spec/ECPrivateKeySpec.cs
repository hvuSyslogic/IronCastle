namespace org.bouncycastle.jce.spec
{

	/// <summary>
	/// Elliptic Curve private key specification.
	/// </summary>
	public class ECPrivateKeySpec : ECKeySpec
	{
		private BigInteger d;

		/// <summary>
		/// base constructor
		/// </summary>
		/// <param name="d"> the private number for the key. </param>
		/// <param name="spec"> the domain parameters for the curve being used. </param>
		public ECPrivateKeySpec(BigInteger d, ECParameterSpec spec) : base(spec)
		{

			this.d = d;
		}

		/// <summary>
		/// return the private number D
		/// </summary>
		public virtual BigInteger getD()
		{
			return d;
		}
	}

}