namespace org.bouncycastle.asn1.dvcs
{
	using PKIStatusInfo = org.bouncycastle.asn1.cmp.PKIStatusInfo;
	using DigestInfo = org.bouncycastle.asn1.x509.DigestInfo;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using PolicyInformation = org.bouncycastle.asn1.x509.PolicyInformation;

	/// <summary>
	/// <pre>
	///     DVCSCertInfo::= SEQUENCE  {
	///         version             Integer DEFAULT 1 ,
	///         dvReqInfo           DVCSRequestInformation,
	///         messageImprint      DigestInfo,
	///         serialNumber        Integer,
	///         responseTime        DVCSTime,
	///         dvStatus            [0] PKIStatusInfo OPTIONAL,
	///         policy              [1] PolicyInformation OPTIONAL,
	///         reqSignature        [2] SignerInfos  OPTIONAL,
	///         certs               [3] SEQUENCE SIZE (1..MAX) OF
	///                                 TargetEtcChain OPTIONAL,
	///         extensions          Extensions OPTIONAL
	///     }
	/// </pre>
	/// </summary>

	public class DVCSCertInfoBuilder
	{

		private int version = DEFAULT_VERSION;
		private DVCSRequestInformation dvReqInfo;
		private DigestInfo messageImprint;
		private ASN1Integer serialNumber;
		private DVCSTime responseTime;
		private PKIStatusInfo dvStatus;
		private PolicyInformation policy;
		private ASN1Set reqSignature;
		private ASN1Sequence certs;
		private Extensions extensions;

		private const int DEFAULT_VERSION = 1;
		private const int TAG_DV_STATUS = 0;
		private const int TAG_POLICY = 1;
		private const int TAG_REQ_SIGNATURE = 2;
		private const int TAG_CERTS = 3;

		public DVCSCertInfoBuilder(DVCSRequestInformation dvReqInfo, DigestInfo messageImprint, ASN1Integer serialNumber, DVCSTime responseTime)
		{
			this.dvReqInfo = dvReqInfo;
			this.messageImprint = messageImprint;
			this.serialNumber = serialNumber;
			this.responseTime = responseTime;
		}

		public virtual DVCSCertInfo build()
		{

			ASN1EncodableVector v = new ASN1EncodableVector();

			if (version != DEFAULT_VERSION)
			{
				v.add(new ASN1Integer(version));
			}
			v.add(dvReqInfo);
			v.add(messageImprint);
			v.add(serialNumber);
			v.add(responseTime);
			if (dvStatus != null)
			{
				v.add(new DERTaggedObject(false, TAG_DV_STATUS, dvStatus));
			}
			if (policy != null)
			{
				v.add(new DERTaggedObject(false, TAG_POLICY, policy));
			}
			if (reqSignature != null)
			{
				v.add(new DERTaggedObject(false, TAG_REQ_SIGNATURE, reqSignature));
			}
			if (certs != null)
			{
				v.add(new DERTaggedObject(false, TAG_CERTS, certs));
			}
			if (extensions != null)
			{
				v.add(extensions);
			}

			return DVCSCertInfo.getInstance(new DERSequence(v));
		}

		public virtual void setVersion(int version)
		{
			this.version = version;
		}

		public virtual void setDvReqInfo(DVCSRequestInformation dvReqInfo)
		{
			this.dvReqInfo = dvReqInfo;
		}

		public virtual void setMessageImprint(DigestInfo messageImprint)
		{
			this.messageImprint = messageImprint;
		}

		public virtual void setSerialNumber(ASN1Integer serialNumber)
		{
			this.serialNumber = serialNumber;
		}

		public virtual void setResponseTime(DVCSTime responseTime)
		{
			this.responseTime = responseTime;
		}

		public virtual void setDvStatus(PKIStatusInfo dvStatus)
		{
			this.dvStatus = dvStatus;
		}

		public virtual void setPolicy(PolicyInformation policy)
		{
			this.policy = policy;
		}

		public virtual void setReqSignature(ASN1Set reqSignature)
		{
			this.reqSignature = reqSignature;
		}

		public virtual void setCerts(TargetEtcChain[] certs)
		{
			this.certs = new DERSequence(certs);
		}

		public virtual void setExtensions(Extensions extensions)
		{
			this.extensions = extensions;
		}

	}

}