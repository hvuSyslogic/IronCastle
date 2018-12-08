namespace org.bouncycastle.jce.spec
{
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;


	/// <summary>
	/// basic domain parameters for an Elliptic Curve public or private key.
	/// </summary>
	public class ECParameterSpec : AlgorithmParameterSpec
	{
		private ECCurve curve;
		private byte[] seed;
		private ECPoint G;
		private BigInteger n;
		private BigInteger h;

		public ECParameterSpec(ECCurve curve, ECPoint G, BigInteger n)
		{
			this.curve = curve;
			this.G = G.normalize();
			this.n = n;
			this.h = BigInteger.valueOf(1);
			this.seed = null;
		}

		public ECParameterSpec(ECCurve curve, ECPoint G, BigInteger n, BigInteger h)
		{
			this.curve = curve;
			this.G = G.normalize();
			this.n = n;
			this.h = h;
			this.seed = null;
		}

		public ECParameterSpec(ECCurve curve, ECPoint G, BigInteger n, BigInteger h, byte[] seed)
		{
			this.curve = curve;
			this.G = G.normalize();
			this.n = n;
			this.h = h;
			this.seed = seed;
		}

		/// <summary>
		/// return the curve along which the base point lies. </summary>
		/// <returns> the curve </returns>
		public virtual ECCurve getCurve()
		{
			return curve;
		}

		/// <summary>
		/// return the base point we are using for these domain parameters. </summary>
		/// <returns> the base point. </returns>
		public virtual ECPoint getG()
		{
			return G;
		}

		/// <summary>
		/// return the order N of G </summary>
		/// <returns> the order </returns>
		public virtual BigInteger getN()
		{
			return n;
		}

		/// <summary>
		/// return the cofactor H to the order of G. </summary>
		/// <returns> the cofactor </returns>
		public virtual BigInteger getH()
		{
			return h;
		}

		/// <summary>
		/// return the seed used to generate this curve (if available). </summary>
		/// <returns> the random seed </returns>
		public virtual byte[] getSeed()
		{
			return seed;
		}

		public override bool Equals(object o)
		{
			if (!(o is ECParameterSpec))
			{
				return false;
			}

			ECParameterSpec other = (ECParameterSpec)o;

			return this.getCurve().Equals(other.getCurve()) && this.getG().Equals(other.getG());
		}

		public override int GetHashCode()
		{
			return this.getCurve().GetHashCode() ^ this.getG().GetHashCode();
		}
	}

}