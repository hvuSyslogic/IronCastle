using BouncyCastle.Core.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	using DHBasicAgreement = org.bouncycastle.crypto.agreement.DHBasicAgreement;
	using ECDHBasicAgreement = org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DHPrivateKeyParameters = org.bouncycastle.crypto.@params.DHPrivateKeyParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	public class DefaultTlsAgreementCredentials : AbstractTlsAgreementCredentials
	{
		protected internal Certificate certificate;
		protected internal AsymmetricKeyParameter privateKey;

		protected internal BasicAgreement basicAgreement;
		protected internal bool truncateAgreement;

		public DefaultTlsAgreementCredentials(Certificate certificate, AsymmetricKeyParameter privateKey)
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

			if (privateKey is DHPrivateKeyParameters)
			{
				basicAgreement = new DHBasicAgreement();
				truncateAgreement = true;
			}
			else if (privateKey is ECPrivateKeyParameters)
			{
				basicAgreement = new ECDHBasicAgreement();
				truncateAgreement = false;
			}
			else
			{
				throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.GetType().getName());
			}

			this.certificate = certificate;
			this.privateKey = privateKey;
		}

		public override Certificate getCertificate()
		{
			return certificate;
		}

		public override byte[] generateAgreement(AsymmetricKeyParameter peerPublicKey)
		{
			basicAgreement.init(privateKey);
			BigInteger agreementValue = basicAgreement.calculateAgreement(peerPublicKey);

			if (truncateAgreement)
			{
				return BigIntegers.asUnsignedByteArray(agreementValue);
			}

			return BigIntegers.asUnsignedByteArray(basicAgreement.getFieldSize(), agreementValue);
		}
	}

}