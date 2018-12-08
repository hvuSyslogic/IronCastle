namespace org.bouncycastle.crypto.tls
{

	public class AbstractTlsCipherFactory : TlsCipherFactory
	{
		public virtual TlsCipher createCipher(TlsContext context, int encryptionAlgorithm, int macAlgorithm)
		{
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}
	}

}