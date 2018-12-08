namespace org.bouncycastle.asn1.esf
{

	public class SigPolicyQualifierInfo : ASN1Object
	{
		private ASN1ObjectIdentifier sigPolicyQualifierId;
		private ASN1Encodable sigQualifier;

		public SigPolicyQualifierInfo(ASN1ObjectIdentifier sigPolicyQualifierId, ASN1Encodable sigQualifier)
		{
			this.sigPolicyQualifierId = sigPolicyQualifierId;
			this.sigQualifier = sigQualifier;
		}

		private SigPolicyQualifierInfo(ASN1Sequence seq)
		{
			sigPolicyQualifierId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
			sigQualifier = seq.getObjectAt(1);
		}

		public static SigPolicyQualifierInfo getInstance(object obj)
		{
			if (obj is SigPolicyQualifierInfo)
			{
				return (SigPolicyQualifierInfo) obj;
			}
			else if (obj != null)
			{
				return new SigPolicyQualifierInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1ObjectIdentifier getSigPolicyQualifierId()
		{
			return new ASN1ObjectIdentifier(sigPolicyQualifierId.getId());
		}

		public virtual ASN1Encodable getSigQualifier()
		{
			return sigQualifier;
		}

		/// <summary>
		/// <pre>
		/// SigPolicyQualifierInfo ::= SEQUENCE {
		///    sigPolicyQualifierId SigPolicyQualifierId,
		///    sigQualifier ANY DEFINED BY sigPolicyQualifierId }
		/// 
		/// SigPolicyQualifierId ::= OBJECT IDENTIFIER
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(sigPolicyQualifierId);
			v.add(sigQualifier);

			return new DERSequence(v);
		}
	}

}