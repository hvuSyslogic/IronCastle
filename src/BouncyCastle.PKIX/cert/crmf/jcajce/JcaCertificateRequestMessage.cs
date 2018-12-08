using org.bouncycastle.asn1;

namespace org.bouncycastle.cert.crmf.jcajce
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using CertReqMsg = org.bouncycastle.asn1.crmf.CertReqMsg;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcaCertificateRequestMessage : CertificateRequestMessage
	{
		private CRMFHelper helper = new CRMFHelper(new DefaultJcaJceHelper());

		public JcaCertificateRequestMessage(byte[] certReqMsg) : this(CertReqMsg.getInstance(certReqMsg))
		{
		}

		public JcaCertificateRequestMessage(CertificateRequestMessage certReqMsg) : this(certReqMsg.toASN1Structure())
		{
		}

		public JcaCertificateRequestMessage(CertReqMsg certReqMsg) : base(certReqMsg)
		{
		}

		public virtual JcaCertificateRequestMessage setProvider(string providerName)
		{
			this.helper = new CRMFHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public virtual JcaCertificateRequestMessage setProvider(Provider provider)
		{
			this.helper = new CRMFHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual X500Principal getSubjectX500Principal()
		{
			X500Name subject = this.getCertTemplate().getSubject();

			if (subject != null)
			{
				try
				{
					return new X500Principal(subject.getEncoded(ASN1Encoding_Fields.DER));
				}
				catch (IOException e)
				{
					throw new IllegalStateException("unable to construct DER encoding of name: " + e.Message);
				}
			}

			return null;
		}

		public virtual PublicKey getPublicKey()
		{
			SubjectPublicKeyInfo subjectPublicKeyInfo = getCertTemplate().getPublicKey();

			if (subjectPublicKeyInfo != null)
			{
				return helper.toPublicKey(subjectPublicKeyInfo);
			}

			return null;
		}
	}

}