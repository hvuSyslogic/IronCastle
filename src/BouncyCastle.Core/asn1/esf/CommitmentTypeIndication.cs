namespace org.bouncycastle.asn1.esf
{

	public class CommitmentTypeIndication : ASN1Object
	{
		private ASN1ObjectIdentifier commitmentTypeId;
		private ASN1Sequence commitmentTypeQualifier;

		private CommitmentTypeIndication(ASN1Sequence seq)
		{
			commitmentTypeId = (ASN1ObjectIdentifier)seq.getObjectAt(0);

			if (seq.size() > 1)
			{
				commitmentTypeQualifier = (ASN1Sequence)seq.getObjectAt(1);
			}
		}

		public CommitmentTypeIndication(ASN1ObjectIdentifier commitmentTypeId)
		{
			this.commitmentTypeId = commitmentTypeId;
		}

		public CommitmentTypeIndication(ASN1ObjectIdentifier commitmentTypeId, ASN1Sequence commitmentTypeQualifier)
		{
			this.commitmentTypeId = commitmentTypeId;
			this.commitmentTypeQualifier = commitmentTypeQualifier;
		}

		public static CommitmentTypeIndication getInstance(object obj)
		{
			if (obj == null || obj is CommitmentTypeIndication)
			{
				return (CommitmentTypeIndication)obj;
			}

			return new CommitmentTypeIndication(ASN1Sequence.getInstance(obj));
		}

		public virtual ASN1ObjectIdentifier getCommitmentTypeId()
		{
			return commitmentTypeId;
		}

		public virtual ASN1Sequence getCommitmentTypeQualifier()
		{
			return commitmentTypeQualifier;
		}

		/// <summary>
		/// <pre>
		/// CommitmentTypeIndication ::= SEQUENCE {
		///      commitmentTypeId   CommitmentTypeIdentifier,
		///      commitmentTypeQualifier   SEQUENCE SIZE (1..MAX) OF
		///              CommitmentTypeQualifier OPTIONAL }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(commitmentTypeId);

			if (commitmentTypeQualifier != null)
			{
				v.add(commitmentTypeQualifier);
			}

			return new DERSequence(v);
		}
	}

}