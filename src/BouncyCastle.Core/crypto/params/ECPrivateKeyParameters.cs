using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class ECPrivateKeyParameters : ECKeyParameters
	{
		internal BigInteger d;

		public ECPrivateKeyParameters(BigInteger d, ECDomainParameters @params) : base(true, @params)
		{
			this.d = d;
		}

		public virtual BigInteger getD()
		{
			return d;
		}
	}

}