namespace org.bouncycastle.asn1.cmp
{
	using CertId = org.bouncycastle.asn1.crmf.CertId;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;

	public class RevAnnContent : ASN1Object
	{
		private PKIStatus status;
		private CertId certId;
		private ASN1GeneralizedTime willBeRevokedAt;
		private ASN1GeneralizedTime badSinceDate;
		private Extensions crlDetails;

		private RevAnnContent(ASN1Sequence seq)
		{
			status = PKIStatus.getInstance(seq.getObjectAt(0));
			certId = CertId.getInstance(seq.getObjectAt(1));
			willBeRevokedAt = ASN1GeneralizedTime.getInstance(seq.getObjectAt(2));
			badSinceDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(3));

			if (seq.size() > 4)
			{
				crlDetails = Extensions.getInstance(seq.getObjectAt(4));
			}
		}

		public static RevAnnContent getInstance(object o)
		{
			if (o is RevAnnContent)
			{
				return (RevAnnContent)o;
			}

			if (o != null)
			{
				return new RevAnnContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual PKIStatus getStatus()
		{
			return status;
		}

		public virtual CertId getCertId()
		{
			return certId;
		}

		public virtual ASN1GeneralizedTime getWillBeRevokedAt()
		{
			return willBeRevokedAt;
		}

		public virtual ASN1GeneralizedTime getBadSinceDate()
		{
			return badSinceDate;
		}

		public virtual Extensions getCrlDetails()
		{
			return crlDetails;
		}

		/// <summary>
		/// <pre>
		/// RevAnnContent ::= SEQUENCE {
		///       status              PKIStatus,
		///       certId              CertId,
		///       willBeRevokedAt     GeneralizedTime,
		///       badSinceDate        GeneralizedTime,
		///       crlDetails          Extensions  OPTIONAL
		///        -- extra CRL details (e.g., crl number, reason, location, etc.)
		/// }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(status);
			v.add(certId);
			v.add(willBeRevokedAt);
			v.add(badSinceDate);

			if (crlDetails != null)
			{
				v.add(crlDetails);
			}

			return new DERSequence(v);
		}
	}

}