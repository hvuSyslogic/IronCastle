namespace org.bouncycastle.jce.spec
{

	/// <summary>
	/// This class specifies a GOST3410-94 public key with its associated parameters.
	/// </summary>

	public class GOST3410PublicKeySpec : KeySpec
	{

		private BigInteger y;
		private BigInteger p;
		private BigInteger q;
		private BigInteger a;

		/// <summary>
		/// Creates a new GOST3410PublicKeySpec with the specified parameter values.
		/// </summary>
		/// <param name="y"> the public key. </param>
		/// <param name="p"> the prime. </param>
		/// <param name="q"> the sub-prime. </param>
		/// <param name="a"> the base. </param>
		public GOST3410PublicKeySpec(BigInteger y, BigInteger p, BigInteger q, BigInteger a)
		{
			this.y = y;
			this.p = p;
			this.q = q;
			this.a = a;
		}

		/// <summary>
		/// Returns the public key <code>y</code>.
		/// </summary>
		/// <returns> the public key <code>y</code>. </returns>
		public virtual BigInteger getY()
		{
			return this.y;
		}

		/// <summary>
		/// Returns the prime <code>p</code>.
		/// </summary>
		/// <returns> the prime <code>p</code>. </returns>
		public virtual BigInteger getP()
		{
			return this.p;
		}

		/// <summary>
		/// Returns the sub-prime <code>q</code>.
		/// </summary>
		/// <returns> the sub-prime <code>q</code>. </returns>
		public virtual BigInteger getQ()
		{
			return this.q;
		}

		/// <summary>
		/// Returns the base <code>g</code>.
		/// </summary>
		/// <returns> the base <code>g</code>. </returns>
		public virtual BigInteger getA()
		{
			return this.a;
		}
	}

}