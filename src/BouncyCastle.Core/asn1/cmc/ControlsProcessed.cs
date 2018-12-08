using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// <pre>
	/// -- Inform follow on servers that one or more controls have already been
	/// -- processed
	/// 
	/// id-cmc-controlProcessed OBJECT IDENTIFIER ::= {id-cmc 32}
	/// 
	/// ControlsProcessed ::= SEQUENCE {
	///     bodyList              SEQUENCE SIZE(1..MAX) OF BodyPartReference
	/// }
	/// </pre>
	/// </summary>
	public class ControlsProcessed : ASN1Object
	{
		private readonly ASN1Sequence bodyPartReferences;

		/// <summary>
		/// Construct a ControlsProcessed object containing one BodyPartReference.
		/// </summary>
		/// <param name="bodyPartRef"> the BodyPartReference to be contained. </param>
		public ControlsProcessed(BodyPartReference bodyPartRef)
		{
			this.bodyPartReferences = new DERSequence(bodyPartRef);
		}


		public ControlsProcessed(BodyPartReference[] bodyList)
		{
			this.bodyPartReferences = new DERSequence(bodyList);
		}


		public static ControlsProcessed getInstance(object src)
		{
			if (src is ControlsProcessed)
			{
				return (ControlsProcessed)src;
			}
			else if (src != null)
			{
				return new ControlsProcessed(ASN1Sequence.getInstance(src));
			}

			return null;
		}

		private ControlsProcessed(ASN1Sequence seq)
		{
			if (seq.size() != 1)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.bodyPartReferences = ASN1Sequence.getInstance(seq.getObjectAt(0));
		}

		public virtual BodyPartReference[] getBodyList()
		{
			BodyPartReference[] tmp = new BodyPartReference[bodyPartReferences.size()];

			for (int i = 0; i != bodyPartReferences.size(); i++)
			{
				tmp[i] = BodyPartReference.getInstance(bodyPartReferences.getObjectAt(i));
			}

			return tmp;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(bodyPartReferences);
		}
	}

}