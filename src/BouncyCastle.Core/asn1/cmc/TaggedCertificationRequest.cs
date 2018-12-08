using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// <pre>
	///       TaggedCertificationRequest ::= SEQUENCE {
	///                  bodyPartID            BodyPartID,
	///                  certificationRequest  CertificationRequest
	///       }
	/// </pre>
	/// </summary>
	public class TaggedCertificationRequest : ASN1Object
	{
		private readonly BodyPartID bodyPartID;
		private readonly CertificationRequest certificationRequest;

		public TaggedCertificationRequest(BodyPartID bodyPartID, CertificationRequest certificationRequest)
		{
			this.bodyPartID = bodyPartID;
			this.certificationRequest = certificationRequest;
		}

		private TaggedCertificationRequest(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
			this.certificationRequest = CertificationRequest.getInstance(seq.getObjectAt(1));
		}

		public static TaggedCertificationRequest getInstance(object o)
		{
			if (o is TaggedCertificationRequest)
			{
				return (TaggedCertificationRequest)o;
			}

			if (o != null)
			{
				return new TaggedCertificationRequest(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public static TaggedCertificationRequest getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(bodyPartID);
			v.add(certificationRequest);

			return new DERSequence(v);
		}
	}

}