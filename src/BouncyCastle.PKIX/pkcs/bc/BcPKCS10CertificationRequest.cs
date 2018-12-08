namespace org.bouncycastle.pkcs.bc
{

	using CertificationRequest = org.bouncycastle.asn1.pkcs.CertificationRequest;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using PublicKeyFactory = org.bouncycastle.crypto.util.PublicKeyFactory;

	public class BcPKCS10CertificationRequest : PKCS10CertificationRequest
	{
		public BcPKCS10CertificationRequest(CertificationRequest certificationRequest) : base(certificationRequest)
		{
		}

		public BcPKCS10CertificationRequest(byte[] encoding) : base(encoding)
		{
		}

		public BcPKCS10CertificationRequest(PKCS10CertificationRequest requestHolder) : base(requestHolder.toASN1Structure())
		{
		}

		public virtual AsymmetricKeyParameter getPublicKey()
		{
			try
			{
				return PublicKeyFactory.createKey(this.getSubjectPublicKeyInfo());
			}
			catch (IOException e)
			{
				throw new PKCSException("error extracting key encoding: " + e.Message, e);
			}
		}
	}

}