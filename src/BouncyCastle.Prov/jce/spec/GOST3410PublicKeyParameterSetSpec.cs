namespace org.bouncycastle.jce.spec
{

	/// <summary>
	/// ParameterSpec for a GOST 3410-94 key parameters.
	/// </summary>
	public class GOST3410PublicKeyParameterSetSpec
	{
		private BigInteger p;
		private BigInteger q;
		private BigInteger a;

		/// <summary>
		/// Creates a new GOST3410ParameterSpec with the specified parameter values.
		/// </summary>
		/// <param name="p"> the prime. </param>
		/// <param name="q"> the sub-prime. </param>
		/// <param name="a"> the base. </param>
		public GOST3410PublicKeyParameterSetSpec(BigInteger p, BigInteger q, BigInteger a)
		{
			this.p = p;
			this.q = q;
			this.a = a;
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
		/// Returns the base <code>a</code>.
		/// </summary>
		/// <returns> the base <code>a</code>. </returns>
		public virtual BigInteger getA()
		{
			return this.a;
		}

		public override bool Equals(object o)
		{
			if (o is GOST3410PublicKeyParameterSetSpec)
			{
				GOST3410PublicKeyParameterSetSpec other = (GOST3410PublicKeyParameterSetSpec)o;

				return this.a.Equals(other.a) && this.p.Equals(other.p) && this.q.Equals(other.q);
			}

			return false;
		}

		public override int GetHashCode()
		{
			return a.GetHashCode() ^ p.GetHashCode() ^ q.GetHashCode();
		}
	}

}