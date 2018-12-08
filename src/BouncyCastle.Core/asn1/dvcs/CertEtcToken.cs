using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.dvcs
{
	using PKIStatusInfo = org.bouncycastle.asn1.cmp.PKIStatusInfo;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using ESSCertID = org.bouncycastle.asn1.ess.ESSCertID;
	using CertID = org.bouncycastle.asn1.ocsp.CertID;
	using CertStatus = org.bouncycastle.asn1.ocsp.CertStatus;
	using OCSPResponse = org.bouncycastle.asn1.ocsp.OCSPResponse;
	using SMIMECapabilities = org.bouncycastle.asn1.smime.SMIMECapabilities;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using Extension = org.bouncycastle.asn1.x509.Extension;

	/// <summary>
	/// <pre>
	/// CertEtcToken ::= CHOICE {
	///         certificate                  [0] IMPLICIT Certificate ,
	///         esscertid                    [1] ESSCertId ,
	///         pkistatus                    [2] IMPLICIT PKIStatusInfo ,
	///         assertion                    [3] ContentInfo ,
	///         crl                          [4] IMPLICIT CertificateList,
	///         ocspcertstatus               [5] CertStatus,
	///         oscpcertid                   [6] IMPLICIT CertId ,
	///         oscpresponse                 [7] IMPLICIT OCSPResponse,
	///         capabilities                 [8] SMIMECapabilities,
	///         extension                    Extension
	/// }
	/// </pre>
	/// </summary>
	public class CertEtcToken : ASN1Object, ASN1Choice
	{
		public const int TAG_CERTIFICATE = 0;
		public const int TAG_ESSCERTID = 1;
		public const int TAG_PKISTATUS = 2;
		public const int TAG_ASSERTION = 3;
		public const int TAG_CRL = 4;
		public const int TAG_OCSPCERTSTATUS = 5;
		public const int TAG_OCSPCERTID = 6;
		public const int TAG_OCSPRESPONSE = 7;
		public const int TAG_CAPABILITIES = 8;

		private static readonly bool[] @explicit = new bool[] {false, true, false, true, false, true, false, false, true};

		private int tagNo;
		private ASN1Encodable value;
		private Extension extension;

		public CertEtcToken(int tagNo, ASN1Encodable value)
		{
			this.tagNo = tagNo;
			this.value = value;
		}

		public CertEtcToken(Extension extension)
		{
			this.tagNo = -1;
			this.extension = extension;
		}

		private CertEtcToken(ASN1TaggedObject choice)
		{
			this.tagNo = choice.getTagNo();

			switch (tagNo)
			{
			case TAG_CERTIFICATE:
				value = Certificate.getInstance(choice, false);
				break;
			case TAG_ESSCERTID:
				value = ESSCertID.getInstance(choice.getObject());
				break;
			case TAG_PKISTATUS:
				value = PKIStatusInfo.getInstance(choice, false);
				break;
			case TAG_ASSERTION:
				value = ContentInfo.getInstance(choice.getObject());
				break;
			case TAG_CRL:
				value = CertificateList.getInstance(choice, false);
				break;
			case TAG_OCSPCERTSTATUS:
				value = CertStatus.getInstance(choice.getObject());
				break;
			case TAG_OCSPCERTID:
				value = CertID.getInstance(choice, false);
				break;
			case TAG_OCSPRESPONSE:
				value = OCSPResponse.getInstance(choice, false);
				break;
			case TAG_CAPABILITIES:
				value = SMIMECapabilities.getInstance(choice.getObject());
				break;
			default:
				throw new IllegalArgumentException("Unknown tag: " + tagNo);
			}
		}

		public static CertEtcToken getInstance(object obj)
		{
			if (obj is CertEtcToken)
			{
				return (CertEtcToken)obj;
			}
			else if (obj is ASN1TaggedObject)
			{
				return new CertEtcToken((ASN1TaggedObject)obj);
			}
			else if (obj != null)
			{
				return new CertEtcToken(Extension.getInstance(obj));
			}

			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			if (extension == null)
			{
				return new DERTaggedObject(@explicit[tagNo], tagNo, value);
			}
			else
			{
				return extension.toASN1Primitive();
			}
		}

		public virtual int getTagNo()
		{
			return tagNo;
		}

		public virtual ASN1Encodable getValue()
		{
			return value;
		}

		public virtual Extension getExtension()
		{
			return extension;
		}

		public override string ToString()
		{
			return "CertEtcToken {\n" + value + "}\n";
		}

		public static CertEtcToken[] arrayFromSequence(ASN1Sequence seq)
		{
			CertEtcToken[] tmp = new CertEtcToken[seq.size()];

			for (int i = 0; i != tmp.Length; i++)
			{
				tmp[i] = CertEtcToken.getInstance(seq.getObjectAt(i));
			}

			return tmp;
		}
	}

}