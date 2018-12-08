using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.tls
{

	public class TlsServerContextImpl : AbstractTlsContext, TlsServerContext
	{
		public TlsServerContextImpl(SecureRandom secureRandom, SecurityParameters securityParameters) : base(secureRandom, securityParameters)
		{
		}

		public override bool isServer()
		{
			return true;
		}
	}

}