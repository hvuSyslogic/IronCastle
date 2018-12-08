namespace org.bouncycastle.asn1.esf
{

	/// <summary>
	/// Commitment type qualifiers, used in the Commitment-Type-Indication attribute (RFC3126).
	/// 
	/// <pre>
	///   CommitmentTypeQualifier ::= SEQUENCE {
	///       commitmentTypeIdentifier  CommitmentTypeIdentifier,
	///       qualifier          ANY DEFINED BY commitmentTypeIdentifier OPTIONAL }
	/// </pre>
	/// </summary>
	public class CommitmentTypeQualifier : ASN1Object
	{
	   private ASN1ObjectIdentifier commitmentTypeIdentifier;
	   private ASN1Encodable qualifier;

	   /// <summary>
	   /// Creates a new <code>CommitmentTypeQualifier</code> instance.
	   /// </summary>
	   /// <param name="commitmentTypeIdentifier"> a <code>CommitmentTypeIdentifier</code> value </param>
		public CommitmentTypeQualifier(ASN1ObjectIdentifier commitmentTypeIdentifier) : this(commitmentTypeIdentifier, null)
		{
		}

	   /// <summary>
	   /// Creates a new <code>CommitmentTypeQualifier</code> instance.
	   /// </summary>
	   /// <param name="commitmentTypeIdentifier"> a <code>CommitmentTypeIdentifier</code> value </param>
	   /// <param name="qualifier"> the qualifier, defined by the above field. </param>
		public CommitmentTypeQualifier(ASN1ObjectIdentifier commitmentTypeIdentifier, ASN1Encodable qualifier)
		{
			this.commitmentTypeIdentifier = commitmentTypeIdentifier;
			this.qualifier = qualifier;
		}

		/// <summary>
		/// Creates a new <code>CommitmentTypeQualifier</code> instance.
		/// </summary>
		/// <param name="as"> <code>CommitmentTypeQualifier</code> structure
		/// encoded as an ASN1Sequence.  </param>
		private CommitmentTypeQualifier(ASN1Sequence @as)
		{
			commitmentTypeIdentifier = (ASN1ObjectIdentifier)@as.getObjectAt(0);

			if (@as.size() > 1)
			{
				qualifier = @as.getObjectAt(1);
			}
		}

		public static CommitmentTypeQualifier getInstance(object @as)
		{
			if (@as is CommitmentTypeQualifier)
			{
				return (CommitmentTypeQualifier)@as;
			}
			else if (@as != null)
			{
				return new CommitmentTypeQualifier(ASN1Sequence.getInstance(@as));
			}

			return null;
		}

		public virtual ASN1ObjectIdentifier getCommitmentTypeIdentifier()
		{
			return commitmentTypeIdentifier;
		}

		public virtual ASN1Encodable getQualifier()
		{
			return qualifier;
		}

	   /// <summary>
	   /// Returns a DER-encodable representation of this instance. 
	   /// </summary>
	   /// <returns> a <code>ASN1Primitive</code> value </returns>
	   public override ASN1Primitive toASN1Primitive()
	   {
		  ASN1EncodableVector dev = new ASN1EncodableVector();
		  dev.add(commitmentTypeIdentifier);
		  if (qualifier != null)
		  {
			  dev.add(qualifier);
		  }

		  return new DERSequence(dev);
	   }
	}

}