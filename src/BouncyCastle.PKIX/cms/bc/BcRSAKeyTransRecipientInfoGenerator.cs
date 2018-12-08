namespace org.bouncycastle.cms.bc
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using BcRSAAsymmetricKeyWrapper = org.bouncycastle.@operator.bc.BcRSAAsymmetricKeyWrapper;

	public class BcRSAKeyTransRecipientInfoGenerator : BcKeyTransRecipientInfoGenerator
	{
		public BcRSAKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, AlgorithmIdentifier encAlgId, AsymmetricKeyParameter publicKey) : base(subjectKeyIdentifier, new BcRSAAsymmetricKeyWrapper(encAlgId, publicKey))
		{
		}

		public BcRSAKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert) : base(recipientCert, new BcRSAAsymmetricKeyWrapper(recipientCert.getSubjectPublicKeyInfo().getAlgorithmId(), recipientCert.getSubjectPublicKeyInfo()))
		{
		}
	}

}