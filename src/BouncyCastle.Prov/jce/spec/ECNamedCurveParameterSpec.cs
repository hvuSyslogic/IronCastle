namespace org.bouncycastle.jce.spec
{

	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// specification signifying that the curve parameters can also be
	/// referred to by name.
	/// <para>
	/// If you are using JDK 1.5 you should be looking at <seealso cref="ECNamedCurveSpec"/>.
	/// </para>
	/// </summary>
	public class ECNamedCurveParameterSpec : ECParameterSpec
	{
		private string name;

		public ECNamedCurveParameterSpec(string name, ECCurve curve, ECPoint G, BigInteger n) : base(curve, G, n)
		{

			this.name = name;
		}

		public ECNamedCurveParameterSpec(string name, ECCurve curve, ECPoint G, BigInteger n, BigInteger h) : base(curve, G, n, h)
		{

			this.name = name;
		}

		public ECNamedCurveParameterSpec(string name, ECCurve curve, ECPoint G, BigInteger n, BigInteger h, byte[] seed) : base(curve, G, n, h, seed)
		{

			this.name = name;
		}

		/// <summary>
		/// return the name of the curve the EC domain parameters belong to.
		/// </summary>
		public virtual string getName()
		{
			return name;
		}
	}

}