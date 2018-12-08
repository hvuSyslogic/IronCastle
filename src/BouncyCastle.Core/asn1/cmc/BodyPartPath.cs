namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// <pre>
	///    BodyPartPath ::= SEQUENCE SIZE (1..MAX) OF BodyPartID
	/// </pre>
	/// </summary>
	public class BodyPartPath : ASN1Object
	{
		private readonly BodyPartID[] bodyPartIDs;

		public static BodyPartPath getInstance(object obj)
		{
			if (obj is BodyPartPath)
			{
				return (BodyPartPath)obj;
			}

			if (obj != null)
			{
				return new BodyPartPath(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static BodyPartPath getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Construct a BodyPartPath object containing one BodyPartID.
		/// </summary>
		/// <param name="bodyPartID"> the BodyPartID to be contained. </param>
		public BodyPartPath(BodyPartID bodyPartID)
		{
			this.bodyPartIDs = new BodyPartID[] {bodyPartID};
		}


		public BodyPartPath(BodyPartID[] bodyPartIDs)
		{
			this.bodyPartIDs = Utils.clone(bodyPartIDs);
		}

		private BodyPartPath(ASN1Sequence seq)
		{
			this.bodyPartIDs = Utils.toBodyPartIDArray(seq);
		}

		public virtual BodyPartID[] getBodyPartIDs()
		{
			return Utils.clone(bodyPartIDs);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(bodyPartIDs);
		}
	}

}