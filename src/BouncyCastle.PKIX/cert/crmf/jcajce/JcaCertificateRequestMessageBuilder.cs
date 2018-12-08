namespace org.bouncycastle.cert.crmf.jcajce
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	public class JcaCertificateRequestMessageBuilder : CertificateRequestMessageBuilder
	{
		public JcaCertificateRequestMessageBuilder(BigInteger certReqId) : base(certReqId)
		{
		}

		public virtual JcaCertificateRequestMessageBuilder setIssuer(X500Principal issuer)
		{
			if (issuer != null)
			{
				setIssuer(X500Name.getInstance(issuer.getEncoded()));
			}

			return this;
		}

		public virtual JcaCertificateRequestMessageBuilder setSubject(X500Principal subject)
		{
			if (subject != null)
			{
				setSubject(X500Name.getInstance(subject.getEncoded()));
			}

			return this;
		}

		public virtual JcaCertificateRequestMessageBuilder setAuthInfoSender(X500Principal sender)
		{
			if (sender != null)
			{
				setAuthInfoSender(new GeneralName(X500Name.getInstance(sender.getEncoded())));
			}

			return this;
		}

		public virtual JcaCertificateRequestMessageBuilder setPublicKey(PublicKey publicKey)
		{
			setPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));

			return this;
		}
	}

}