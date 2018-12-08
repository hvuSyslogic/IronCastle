using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using ReasonFlags = org.bouncycastle.asn1.x509.ReasonFlags;

	/// <summary>
	/// <pre>
	/// id-cmc-getCRL OBJECT IDENTIFIER ::= {id-cmc 16}
	/// 
	/// GetCRL ::= SEQUENCE {
	///    issuerName    Name,
	///    cRLName       GeneralName OPTIONAL,
	///    time          GeneralizedTime OPTIONAL,
	///    reasons       ReasonFlags OPTIONAL }
	/// </pre>
	/// </summary>
	public class GetCRL : ASN1Object
	{
		private readonly X500Name issuerName;
		private GeneralName cRLName;
		private ASN1GeneralizedTime time;
		private ReasonFlags reasons;

		public GetCRL(X500Name issuerName, GeneralName cRLName, ASN1GeneralizedTime time, ReasonFlags reasons)
		{
			this.issuerName = issuerName;
			this.cRLName = cRLName;
			this.time = time;
			this.reasons = reasons;
		}


		private GetCRL(ASN1Sequence seq)
		{
			if (seq.size() < 1 || seq.size() > 4)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.issuerName = X500Name.getInstance(seq.getObjectAt(0));

			int index = 1;
			if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() is ASN1TaggedObject)
			{
				this.cRLName = GeneralName.getInstance(seq.getObjectAt(index++));
			}
			if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() is ASN1GeneralizedTime)
			{
				this.time = ASN1GeneralizedTime.getInstance(seq.getObjectAt(index++));
			}
			if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() is DERBitString)
			{
				this.reasons = new ReasonFlags(DERBitString.getInstance(seq.getObjectAt(index)));
			}
		}

		public static GetCRL getInstance(object o)
		{
			if (o is GetCRL)
			{
				return (GetCRL)o;
			}

			if (o != null)
			{
				return new GetCRL(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual X500Name getIssuerName()
		{
			return issuerName;
		}

		public virtual GeneralName getcRLName()
		{
			return cRLName;
		}

		public virtual ASN1GeneralizedTime getTime()
		{
			return time;
		}

		public virtual ReasonFlags getReasons()
		{
			return reasons;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(issuerName);
			if (cRLName != null)
			{
				v.add(cRLName);
			}
			if (time != null)
			{
				v.add(time);
			}
			if (reasons != null)
			{
				v.add(reasons);
			}

			return new DERSequence(v);
		}
	}

}