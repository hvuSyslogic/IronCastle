namespace org.bouncycastle.cert.cmp
{

	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using RevDetails = org.bouncycastle.asn1.cmp.RevDetails;
	using CertTemplateBuilder = org.bouncycastle.asn1.crmf.CertTemplateBuilder;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	public class RevocationDetailsBuilder
	{
		private CertTemplateBuilder templateBuilder = new CertTemplateBuilder();

		public virtual RevocationDetailsBuilder setPublicKey(SubjectPublicKeyInfo publicKey)
		{
			if (publicKey != null)
			{
				templateBuilder.setPublicKey(publicKey);
			}

			return this;
		}

		public virtual RevocationDetailsBuilder setIssuer(X500Name issuer)
		{
			if (issuer != null)
			{
				templateBuilder.setIssuer(issuer);
			}

			return this;
		}

		public virtual RevocationDetailsBuilder setSerialNumber(BigInteger serialNumber)
		{
			if (serialNumber != null)
			{
				templateBuilder.setSerialNumber(new ASN1Integer(serialNumber));
			}

			return this;
		}

		public virtual RevocationDetailsBuilder setSubject(X500Name subject)
		{
			if (subject != null)
			{
				templateBuilder.setSubject(subject);
			}

			return this;
		}

		public virtual RevocationDetails build()
		{
			return new RevocationDetails(new RevDetails(templateBuilder.build()));
		}
	}

}