namespace org.bouncycastle.crypto.tls.test
{

	public class DTLSTestServerProtocol : DTLSServerProtocol
	{
		protected internal readonly TlsTestConfig config;

		public DTLSTestServerProtocol(SecureRandom secureRandom, TlsTestConfig config) : base(secureRandom)
		{

			this.config = config;
		}
	}

}