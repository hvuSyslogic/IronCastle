namespace org.bouncycastle.crypto.tls.test
{


	public class DTLSTestClientProtocol : DTLSClientProtocol
	{
		protected internal readonly TlsTestConfig config;

		public DTLSTestClientProtocol(SecureRandom secureRandom, TlsTestConfig config) : base(secureRandom)
		{

			this.config = config;
		}

		public override byte[] generateCertificateVerify(ClientHandshakeState state, DigitallySigned certificateVerify)
		{
			if (certificateVerify.getAlgorithm() != null && config.clientAuthSigAlgClaimed != null)
			{
				certificateVerify = new DigitallySigned(config.clientAuthSigAlgClaimed, certificateVerify.getSignature());
			}

			return base.generateCertificateVerify(state, certificateVerify);
		}
	}

}