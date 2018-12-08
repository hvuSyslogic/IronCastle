namespace org.bouncycastle.asn1.est
{

	/// <summary>
	/// <pre>
	///      CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
	/// </pre>
	/// </summary>
	public class CsrAttrs : ASN1Object
	{
		private readonly AttrOrOID[] attrOrOIDs;

		public static CsrAttrs getInstance(object obj)
		{
			if (obj is CsrAttrs)
			{
				return (CsrAttrs)obj;
			}

			if (obj != null)
			{
				return new CsrAttrs(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static CsrAttrs getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Construct a CsrAttrs object containing one AttrOrOID.
		/// </summary>
		/// <param name="attrOrOID"> the AttrOrOID to be contained. </param>
		public CsrAttrs(AttrOrOID attrOrOID)
		{
			this.attrOrOIDs = new AttrOrOID[]{attrOrOID};
		}


		public CsrAttrs(AttrOrOID[] attrOrOIDs)
		{
			this.attrOrOIDs = Utils.clone(attrOrOIDs);
		}

		private CsrAttrs(ASN1Sequence seq)
		{
			this.attrOrOIDs = new AttrOrOID[seq.size()];

			for (int i = 0; i != seq.size(); i++)
			{
				attrOrOIDs[i] = AttrOrOID.getInstance(seq.getObjectAt(i));
			}
		}

		public virtual AttrOrOID[] getAttrOrOIDs()
		{
			return Utils.clone(attrOrOIDs);
		}

		public virtual int size()
		{
			return attrOrOIDs.Length;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(attrOrOIDs);
		}
	}

}