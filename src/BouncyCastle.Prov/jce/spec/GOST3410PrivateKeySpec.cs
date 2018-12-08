namespace org.bouncycastle.jce.spec
{

	/// <summary>
	/// This class specifies a GOST3410-94 private key with its associated parameters.
	/// </summary>

	public class GOST3410PrivateKeySpec : KeySpec
	{
		private BigInteger x;
		private BigInteger p;
		private BigInteger q;
		private BigInteger a;

		/// <summary>
		/// Creates a new GOST3410PrivateKeySpec with the specified parameter values.
		/// </summary>
		/// <param name="x"> the private key. </param>
		/// <param name="p"> the prime. </param>
		/// <param name="q"> the sub-prime. </param>
		/// <param name="a"> the base. </param>
		public GOST3410PrivateKeySpec(BigInteger x, BigInteger p, BigInteger q, BigInteger a)
		{
			this.x = x;
			this.p = p;
			this.q = q;
			this.a = a;
		}

		/// <summary>
		/// Returns the private key <code>x</code>. </summary>
		/// <returns> the private key <code>x</code>. </returns>
		public virtual BigInteger getX()
		{
			return this.x;
		}

		/// <summary>
		/// Returns the prime <code>p</code>. </summary>
		/// <returns> the prime <code>p</code>. </returns>
		public virtual BigInteger getP()
		{
			return this.p;
		}

		/// <summary>
		/// Returns the sub-prime <code>q</code>. </summary>
		/// <returns> the sub-prime <code>q</code>. </returns>
		public virtual BigInteger getQ()
		{
			return this.q;
		}

		/// <summary>
		/// Returns the base <code>a</code>. </summary>
		/// <returns> the base <code>a</code>. </returns>
		public virtual BigInteger getA()
		{
			return this.a;
		}
	}

}