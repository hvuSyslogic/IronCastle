using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.tls
{

	public class TlsClientContextImpl : AbstractTlsContext, TlsClientContext
	{
		public TlsClientContextImpl(SecureRandom secureRandom, SecurityParameters securityParameters) : base(secureRandom, securityParameters)
		{
		}

		public override bool isServer()
		{
			return false;
		}
	}

}