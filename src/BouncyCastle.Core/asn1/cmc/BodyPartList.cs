namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// <pre>
	///   BodyPartList ::= SEQUENCE SIZE (1..MAX) OF BodyPartID
	/// </pre>
	/// </summary>
	public class BodyPartList : ASN1Object
	{
		private readonly BodyPartID[] bodyPartIDs;

		public static BodyPartList getInstance(object obj)
		{
			if (obj is BodyPartList)
			{
				return (BodyPartList)obj;
			}

			if (obj != null)
			{
				return new BodyPartList(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static BodyPartList getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Construct a BodyPartList object containing one BodyPartID.
		/// </summary>
		/// <param name="bodyPartID"> the BodyPartID to be contained. </param>
		public BodyPartList(BodyPartID bodyPartID)
		{
			this.bodyPartIDs = new BodyPartID[] {bodyPartID};
		}


		public BodyPartList(BodyPartID[] bodyPartIDs)
		{
			this.bodyPartIDs = Utils.clone(bodyPartIDs);
		}

		private BodyPartList(ASN1Sequence seq)
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