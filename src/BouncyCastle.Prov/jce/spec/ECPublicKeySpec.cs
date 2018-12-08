namespace org.bouncycastle.jce.spec
{
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// Elliptic Curve public key specification
	/// </summary>
	public class ECPublicKeySpec : ECKeySpec
	{
		private ECPoint q;

		/// <summary>
		/// base constructor
		/// </summary>
		/// <param name="q"> the public point on the curve. </param>
		/// <param name="spec"> the domain parameters for the curve. </param>
		public ECPublicKeySpec(ECPoint q, ECParameterSpec spec) : base(spec)
		{

			if (q.getCurve() != null)
			{
				this.q = q.normalize();
			}
			else
			{
				this.q = q;
			}
		}

		/// <summary>
		/// return the public point q
		/// </summary>
		public virtual ECPoint getQ()
		{
			return q;
		}
	}

}