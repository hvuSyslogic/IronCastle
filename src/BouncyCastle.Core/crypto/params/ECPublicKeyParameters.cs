using org.bouncycastle.math.ec;

namespace org.bouncycastle.crypto.@params
{
	
	public class ECPublicKeyParameters : ECKeyParameters
	{
		private readonly ECPoint Q;

		public ECPublicKeyParameters(ECPoint Q, ECDomainParameters @params) : base(false, @params)
		{

			this.Q = ECDomainParameters.validate(@params.getCurve(), Q);
		}

		public virtual ECPoint getQ()
		{
			return Q;
		}
	}

}