namespace org.bouncycastle.crypto.tls.test
{


	public class TlsTestClientProtocol : TlsClientProtocol
	{
		protected internal readonly TlsTestConfig config;

		public TlsTestClientProtocol(InputStream input, OutputStream output, SecureRandom secureRandom, TlsTestConfig config) : base(input, output, secureRandom)
		{

			this.config = config;
		}

		public override void sendCertificateVerifyMessage(DigitallySigned certificateVerify)
		{
			if (certificateVerify.getAlgorithm() != null && config.clientAuthSigAlgClaimed != null)
			{
				certificateVerify = new DigitallySigned(config.clientAuthSigAlgClaimed, certificateVerify.getSignature());
			}

			base.sendCertificateVerifyMessage(certificateVerify);
		}
	}

}