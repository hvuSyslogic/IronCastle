using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmp
{

	public class CertResponse : ASN1Object
	{
		private ASN1Integer certReqId;
		private PKIStatusInfo status;
		private CertifiedKeyPair certifiedKeyPair;
		private ASN1OctetString rspInfo;

		private CertResponse(ASN1Sequence seq)
		{
			certReqId = ASN1Integer.getInstance(seq.getObjectAt(0));
			status = PKIStatusInfo.getInstance(seq.getObjectAt(1));

			if (seq.size() >= 3)
			{
				if (seq.size() == 3)
				{
					ASN1Encodable o = seq.getObjectAt(2);
					if (o is ASN1OctetString)
					{
						rspInfo = ASN1OctetString.getInstance(o);
					}
					else
					{
						certifiedKeyPair = CertifiedKeyPair.getInstance(o);
					}
				}
				else
				{
					certifiedKeyPair = CertifiedKeyPair.getInstance(seq.getObjectAt(2));
					rspInfo = ASN1OctetString.getInstance(seq.getObjectAt(3));
				}
			}
		}

		public static CertResponse getInstance(object o)
		{
			if (o is CertResponse)
			{
				return (CertResponse)o;
			}

			if (o != null)
			{
				return new CertResponse(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public CertResponse(ASN1Integer certReqId, PKIStatusInfo status) : this(certReqId, status, null, null)
		{
		}

		public CertResponse(ASN1Integer certReqId, PKIStatusInfo status, CertifiedKeyPair certifiedKeyPair, ASN1OctetString rspInfo)
		{
			if (certReqId == null)
			{
				throw new IllegalArgumentException("'certReqId' cannot be null");
			}
			if (status == null)
			{
				throw new IllegalArgumentException("'status' cannot be null");
			}
			this.certReqId = certReqId;
			this.status = status;
			this.certifiedKeyPair = certifiedKeyPair;
			this.rspInfo = rspInfo;
		}

		public virtual ASN1Integer getCertReqId()
		{
			return certReqId;
		}

		public virtual PKIStatusInfo getStatus()
		{
			return status;
		}

		public virtual CertifiedKeyPair getCertifiedKeyPair()
		{
			return certifiedKeyPair;
		}

		/// <summary>
		/// <pre>
		/// CertResponse ::= SEQUENCE {
		///                            certReqId           INTEGER,
		///                            -- to match this response with corresponding request (a value
		///                            -- of -1 is to be used if certReqId is not specified in the
		///                            -- corresponding request)
		///                            status              PKIStatusInfo,
		///                            certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
		///                            rspInfo             OCTET STRING        OPTIONAL
		///                            -- analogous to the id-regInfo-utf8Pairs string defined
		///                            -- for regInfo in CertReqMsg [CRMF]
		///             }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certReqId);
			v.add(status);

			if (certifiedKeyPair != null)
			{
				v.add(certifiedKeyPair);
			}

			if (rspInfo != null)
			{
				v.add(rspInfo);
			}

			return new DERSequence(v);
		}
	}

}