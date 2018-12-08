using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class DSAPrivateKeyParameters : DSAKeyParameters
	{
		private BigInteger x;

		public DSAPrivateKeyParameters(BigInteger x, DSAParameters @params) : base(true, @params)
		{

			this.x = x;
		}

		public virtual BigInteger getX()
		{
			return x;
		}
	}

}