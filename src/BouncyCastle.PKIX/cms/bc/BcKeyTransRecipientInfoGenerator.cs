namespace org.bouncycastle.cms.bc
{
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using BcAsymmetricKeyWrapper = org.bouncycastle.@operator.bc.BcAsymmetricKeyWrapper;

	public abstract class BcKeyTransRecipientInfoGenerator : KeyTransRecipientInfoGenerator
	{
		public BcKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert, BcAsymmetricKeyWrapper wrapper) : base(new IssuerAndSerialNumber(recipientCert.toASN1Structure()), wrapper)
		{
		}

		public BcKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, BcAsymmetricKeyWrapper wrapper) : base(subjectKeyIdentifier, wrapper)
		{
		}
	}
}