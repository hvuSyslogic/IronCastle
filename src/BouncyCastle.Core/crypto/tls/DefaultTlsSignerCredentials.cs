using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

				
	public class DefaultTlsSignerCredentials : AbstractTlsSignerCredentials
	{
		protected internal TlsContext context;
		protected internal Certificate certificate;
		protected internal AsymmetricKeyParameter privateKey;
		protected internal SignatureAndHashAlgorithm signatureAndHashAlgorithm;

		protected internal TlsSigner signer;

		public DefaultTlsSignerCredentials(TlsContext context, Certificate certificate, AsymmetricKeyParameter privateKey) : this(context, certificate, privateKey, null)
		{
		}

		public DefaultTlsSignerCredentials(TlsContext context, Certificate certificate, AsymmetricKeyParameter privateKey, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
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
			if (TlsUtils.isTLSv12(context) && signatureAndHashAlgorithm == null)
			{
				throw new IllegalArgumentException("'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+");
			}

			if (privateKey is RSAKeyParameters)
			{
				this.signer = new TlsRSASigner();
			}
			else if (privateKey is DSAPrivateKeyParameters)
			{
				this.signer = new TlsDSSSigner();
			}
			else if (privateKey is ECPrivateKeyParameters)
			{
				this.signer = new TlsECDSASigner();
			}
			else
			{
				throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.GetType().getName());
			}

			this.signer.init(context);

			this.context = context;
			this.certificate = certificate;
			this.privateKey = privateKey;
			this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
		}

		public override Certificate getCertificate()
		{
			return certificate;
		}

		public override byte[] generateCertificateSignature(byte[] hash)
		{
			try
			{
				if (TlsUtils.isTLSv12(context))
				{
					return signer.generateRawSignature(signatureAndHashAlgorithm, privateKey, hash);
				}
				else
				{
					return signer.generateRawSignature(privateKey, hash);
				}
			}
			catch (CryptoException e)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error, e);
			}
		}

		public override SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
		{
			return signatureAndHashAlgorithm;
		}
	}

}