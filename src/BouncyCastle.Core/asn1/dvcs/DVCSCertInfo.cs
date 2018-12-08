using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

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

	public class DVCSCertInfo : ASN1Object
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

		public DVCSCertInfo(DVCSRequestInformation dvReqInfo, DigestInfo messageImprint, ASN1Integer serialNumber, DVCSTime responseTime)
		{
			this.dvReqInfo = dvReqInfo;
			this.messageImprint = messageImprint;
			this.serialNumber = serialNumber;
			this.responseTime = responseTime;
		}

		private DVCSCertInfo(ASN1Sequence seq)
		{
			int i = 0;
			ASN1Encodable x = seq.getObjectAt(i++);
			try
			{
				ASN1Integer encVersion = ASN1Integer.getInstance(x);
				this.version = encVersion.getValue().intValue();
				x = seq.getObjectAt(i++);
			}
			catch (IllegalArgumentException)
			{
			}

			this.dvReqInfo = DVCSRequestInformation.getInstance(x);
			x = seq.getObjectAt(i++);
			this.messageImprint = DigestInfo.getInstance(x);
			x = seq.getObjectAt(i++);
			this.serialNumber = ASN1Integer.getInstance(x);
			x = seq.getObjectAt(i++);
			this.responseTime = DVCSTime.getInstance(x);

			while (i < seq.size())
			{

				x = seq.getObjectAt(i++);

				if (x is ASN1TaggedObject)
				{
					ASN1TaggedObject t = ASN1TaggedObject.getInstance(x);
					int tagNo = t.getTagNo();

					switch (tagNo)
					{
					case TAG_DV_STATUS:
						this.dvStatus = PKIStatusInfo.getInstance(t, false);
						break;
					case TAG_POLICY:
						this.policy = PolicyInformation.getInstance(ASN1Sequence.getInstance(t, false));
						break;
					case TAG_REQ_SIGNATURE:
						this.reqSignature = ASN1Set.getInstance(t, false);
						break;
					case TAG_CERTS:
						this.certs = ASN1Sequence.getInstance(t, false);
						break;
					default:
						throw new IllegalArgumentException("Unknown tag encountered: " + tagNo);
					}

					continue;
				}

				try
				{
					this.extensions = Extensions.getInstance(x);
				}
				catch (IllegalArgumentException)
				{
				}

			}

		}

		public static DVCSCertInfo getInstance(object obj)
		{
			if (obj is DVCSCertInfo)
			{
				return (DVCSCertInfo)obj;
			}
			else if (obj != null)
			{
				return new DVCSCertInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static DVCSCertInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public override ASN1Primitive toASN1Primitive()
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

			return new DERSequence(v);
		}

		public override string ToString()
		{
			StringBuffer s = new StringBuffer();

			s.append("DVCSCertInfo {\n");

			if (version != DEFAULT_VERSION)
			{
				s.append("version: " + version + "\n");
			}
			s.append("dvReqInfo: " + dvReqInfo + "\n");
			s.append("messageImprint: " + messageImprint + "\n");
			s.append("serialNumber: " + serialNumber + "\n");
			s.append("responseTime: " + responseTime + "\n");
			if (dvStatus != null)
			{
				s.append("dvStatus: " + dvStatus + "\n");
			}
			if (policy != null)
			{
				s.append("policy: " + policy + "\n");
			}
			if (reqSignature != null)
			{
				s.append("reqSignature: " + reqSignature + "\n");
			}
			if (certs != null)
			{
				s.append("certs: " + certs + "\n");
			}
			if (extensions != null)
			{
				s.append("extensions: " + extensions + "\n");
			}

			s.append("}\n");
			return s.ToString();
		}

		public virtual int getVersion()
		{
			return version;
		}

		private void setVersion(int version)
		{
			this.version = version;
		}

		public virtual DVCSRequestInformation getDvReqInfo()
		{
			return dvReqInfo;
		}

		private void setDvReqInfo(DVCSRequestInformation dvReqInfo)
		{
			this.dvReqInfo = dvReqInfo;
		}

		public virtual DigestInfo getMessageImprint()
		{
			return messageImprint;
		}

		private void setMessageImprint(DigestInfo messageImprint)
		{
			this.messageImprint = messageImprint;
		}

		public virtual ASN1Integer getSerialNumber()
		{
			return serialNumber;
		}

		public virtual DVCSTime getResponseTime()
		{
			return responseTime;
		}

		public virtual PKIStatusInfo getDvStatus()
		{
			return dvStatus;
		}

		public virtual PolicyInformation getPolicy()
		{
			return policy;
		}

		public virtual ASN1Set getReqSignature()
		{
			return reqSignature;
		}

		public virtual TargetEtcChain[] getCerts()
		{
			if (certs != null)
			{
				return TargetEtcChain.arrayFromSequence(certs);
			}

			return null;
		}

		public virtual Extensions getExtensions()
		{
			return extensions;
		}
	}

}