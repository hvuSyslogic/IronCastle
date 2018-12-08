namespace org.bouncycastle.asn1.esf
{

	public class SigPolicyQualifiers : ASN1Object
	{
		internal ASN1Sequence qualifiers;

		public static SigPolicyQualifiers getInstance(object obj)
		{
			if (obj is SigPolicyQualifiers)
			{
				return (SigPolicyQualifiers) obj;
			}
			else if (obj is ASN1Sequence)
			{
				return new SigPolicyQualifiers(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private SigPolicyQualifiers(ASN1Sequence seq)
		{
			qualifiers = seq;
		}

		public SigPolicyQualifiers(SigPolicyQualifierInfo[] qualifierInfos)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i < qualifierInfos.Length; i++)
			{
				v.add(qualifierInfos[i]);
			}
			qualifiers = new DERSequence(v);
		}

		/// <summary>
		/// Return the number of qualifier info elements present.
		/// </summary>
		/// <returns> number of elements present. </returns>
		public virtual int size()
		{
			return qualifiers.size();
		}

		/// <summary>
		/// Return the SigPolicyQualifierInfo at index i.
		/// </summary>
		/// <param name="i"> index of the info of interest </param>
		/// <returns> the info at index i. </returns>
		public virtual SigPolicyQualifierInfo getInfoAt(int i)
		{
			return SigPolicyQualifierInfo.getInstance(qualifiers.getObjectAt(i));
		}

		/// <summary>
		/// <pre>
		/// SigPolicyQualifiers ::= SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return qualifiers;
		}
	}

}