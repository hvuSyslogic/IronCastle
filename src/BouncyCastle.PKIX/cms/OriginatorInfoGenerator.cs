namespace org.bouncycastle.cms
{

	using OriginatorInfo = org.bouncycastle.asn1.cms.OriginatorInfo;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using Store = org.bouncycastle.util.Store;

	public class OriginatorInfoGenerator
	{
		private readonly List origCerts;
		private readonly List origCRLs;

		public OriginatorInfoGenerator(X509CertificateHolder origCert)
		{
			this.origCerts = new ArrayList(1);
			this.origCRLs = null;
			origCerts.add(origCert.toASN1Structure());
		}

		public OriginatorInfoGenerator(Store origCerts) : this(origCerts, null)
		{
		}

		public OriginatorInfoGenerator(Store origCerts, Store origCRLs)
		{
			this.origCerts = CMSUtils.getCertificatesFromStore(origCerts);

			if (origCRLs != null)
			{
				this.origCRLs = CMSUtils.getCRLsFromStore(origCRLs);
			}
			else
			{
				this.origCRLs = null;
			}
		}

		public virtual OriginatorInformation generate()
		{
			if (origCRLs != null)
			{
				return new OriginatorInformation(new OriginatorInfo(CMSUtils.createDerSetFromList(origCerts), CMSUtils.createDerSetFromList(origCRLs)));
			}
			else
			{
				return new OriginatorInformation(new OriginatorInfo(CMSUtils.createDerSetFromList(origCerts), null));
			}
		}
	}

}