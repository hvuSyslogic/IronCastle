using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// Public key parameters for NaccacheStern cipher. For details on this cipher,
	/// please see
	/// 
	/// http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
	/// </summary>
	public class NaccacheSternKeyParameters : AsymmetricKeyParameter
	{

		private BigInteger g, n;

		internal int lowerSigmaBound;

		/// <param name="privateKey"> </param>
		public NaccacheSternKeyParameters(bool privateKey, BigInteger g, BigInteger n, int lowerSigmaBound) : base(privateKey)
		{
			this.g = g;
			this.n = n;
			this.lowerSigmaBound = lowerSigmaBound;
		}

		/// <returns> Returns the g. </returns>
		public virtual BigInteger getG()
		{
			return g;
		}

		/// <returns> Returns the lowerSigmaBound. </returns>
		public virtual int getLowerSigmaBound()
		{
			return lowerSigmaBound;
		}

		/// <returns> Returns the n. </returns>
		public virtual BigInteger getModulus()
		{
			return n;
		}

	}

}