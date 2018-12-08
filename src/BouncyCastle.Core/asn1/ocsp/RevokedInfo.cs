namespace org.bouncycastle.asn1.ocsp
{
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;

	public class RevokedInfo : ASN1Object
	{
		private ASN1GeneralizedTime revocationTime;
		private CRLReason revocationReason;

		public RevokedInfo(ASN1GeneralizedTime revocationTime, CRLReason revocationReason)
		{
			this.revocationTime = revocationTime;
			this.revocationReason = revocationReason;
		}

		private RevokedInfo(ASN1Sequence seq)
		{
			this.revocationTime = ASN1GeneralizedTime.getInstance(seq.getObjectAt(0));

			if (seq.size() > 1)
			{
				this.revocationReason = CRLReason.getInstance(ASN1Enumerated.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true));
			}
		}

		public static RevokedInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static RevokedInfo getInstance(object obj)
		{
			if (obj is RevokedInfo)
			{
				return (RevokedInfo)obj;
			}
			else if (obj != null)
			{
				return new RevokedInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1GeneralizedTime getRevocationTime()
		{
			return revocationTime;
		}

		public virtual CRLReason getRevocationReason()
		{
			return revocationReason;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// RevokedInfo ::= SEQUENCE {
		///      revocationTime              GeneralizedTime,
		///      revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(revocationTime);
			if (revocationReason != null)
			{
				v.add(new DERTaggedObject(true, 0, revocationReason));
			}

			return new DERSequence(v);
		}
	}

}