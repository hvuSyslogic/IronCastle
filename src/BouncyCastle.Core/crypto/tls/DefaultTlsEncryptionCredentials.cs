using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;

	public class DefaultTlsEncryptionCredentials : AbstractTlsEncryptionCredentials
	{
		protected internal TlsContext context;
		protected internal Certificate certificate;
		protected internal AsymmetricKeyParameter privateKey;

		public DefaultTlsEncryptionCredentials(TlsContext context, Certificate certificate, AsymmetricKeyParameter privateKey)
		{
			if (certificate == null)
			{
				throw new IllegalArgumentException("'certificate' cannot be null");
			}
			if (certificate.isEmpty())
			{
				throw new IllegalArgumentException("'certificate' cannot be empty");
			}
			if (privateKey == null)
			{
				throw new IllegalArgumentException("'privateKey' cannot be null");
			}
			if (!privateKey.isPrivate())
			{
				throw new IllegalArgumentException("'privateKey' must be private");
			}

			if (privateKey is RSAKeyParameters)
			{
			}
			else
			{
				throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.GetType().getName());
			}

			this.context = context;
			this.certificate = certificate;
			this.privateKey = privateKey;
		}

		public override Certificate getCertificate()
		{
			return certificate;
		}

		public override byte[] decryptPreMasterSecret(byte[] encryptedPreMasterSecret)
		{
			return TlsRSAUtils.safeDecryptPreMasterSecret(context, (RSAKeyParameters)privateKey, encryptedPreMasterSecret);
		}
	}

}