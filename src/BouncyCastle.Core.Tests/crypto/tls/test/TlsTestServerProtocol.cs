namespace org.bouncycastle.crypto.tls.test
{

	public class TlsTestServerProtocol : TlsServerProtocol
	{
		protected internal readonly TlsTestConfig config;

		public TlsTestServerProtocol(InputStream input, OutputStream output, SecureRandom secureRandom, TlsTestConfig config) : base(input, output, secureRandom)
		{

			this.config = config;
		}
	}

}