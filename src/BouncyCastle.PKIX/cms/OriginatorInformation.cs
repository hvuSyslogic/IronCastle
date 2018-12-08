namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using OriginatorInfo = org.bouncycastle.asn1.cms.OriginatorInfo;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using CollectionStore = org.bouncycastle.util.CollectionStore;
	using Store = org.bouncycastle.util.Store;

	public class OriginatorInformation
	{
		private OriginatorInfo originatorInfo;

		public OriginatorInformation(OriginatorInfo originatorInfo)
		{
			this.originatorInfo = originatorInfo;
		}

		/// <summary>
		/// Return the certificates stored in the underlying OriginatorInfo object.
		/// </summary>
		/// <returns> a Store of X509CertificateHolder objects. </returns>
		public virtual Store getCertificates()
		{
			ASN1Set certSet = originatorInfo.getCertificates();

			if (certSet != null)
			{
				List certList = new ArrayList(certSet.size());

				for (Enumeration en = certSet.getObjects(); en.hasMoreElements();)
				{
					ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

					if (obj is ASN1Sequence)
					{
						certList.add(new X509CertificateHolder(Certificate.getInstance(obj)));
					}
				}

				return new CollectionStore(certList);
			}

			return new CollectionStore(new ArrayList());
		}

		/// <summary>
		/// Return the CRLs stored in the underlying OriginatorInfo object.
		/// </summary>
		/// <returns> a Store of X509CRLHolder objects. </returns>
		public virtual Store getCRLs()
		{
			ASN1Set crlSet = originatorInfo.getCRLs();

			if (crlSet != null)
			{
				List crlList = new ArrayList(crlSet.size());

				for (Enumeration en = crlSet.getObjects(); en.hasMoreElements();)
				{
					ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

					if (obj is ASN1Sequence)
					{
						crlList.add(new X509CRLHolder(CertificateList.getInstance(obj)));
					}
				}

				return new CollectionStore(crlList);
			}

			return new CollectionStore(new ArrayList());
		}

		/// <summary>
		/// Return the underlying ASN.1 object defining this SignerInformation object.
		/// </summary>
		/// <returns> a OriginatorInfo. </returns>
		public virtual OriginatorInfo toASN1Structure()
		{
			return originatorInfo;
		}
	}

}