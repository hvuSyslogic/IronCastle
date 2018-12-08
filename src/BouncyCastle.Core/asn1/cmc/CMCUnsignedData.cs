using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// <pre>
	///      id-aa-cmc-unsignedData OBJECT IDENTIFIER ::= {id-aa 34}
	/// 
	///      CMCUnsignedData ::= SEQUENCE {
	///             bodyPartPath        BodyPartPath,
	///             identifier          OBJECT IDENTIFIER,
	///             content             ANY DEFINED BY identifier
	///      }
	/// </pre>
	/// </summary>
	public class CMCUnsignedData : ASN1Object
	{
		private readonly BodyPartPath bodyPartPath;
		private readonly ASN1ObjectIdentifier identifier;
		private readonly ASN1Encodable content;

		public CMCUnsignedData(BodyPartPath bodyPartPath, ASN1ObjectIdentifier identifier, ASN1Encodable content)
		{
			this.bodyPartPath = bodyPartPath;
			this.identifier = identifier;
			this.content = content;
		}

		private CMCUnsignedData(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.bodyPartPath = BodyPartPath.getInstance(seq.getObjectAt(0));
			this.identifier = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
			this.content = seq.getObjectAt(2);
		}

		public static CMCUnsignedData getInstance(object o)
		{
			if (o is CMCUnsignedData)
			{
				return (CMCUnsignedData)o;
			}

			if (o != null)
			{
				return new CMCUnsignedData(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(bodyPartPath);
			v.add(identifier);
			v.add(content);

			return new DERSequence(v);
		}

		public virtual BodyPartPath getBodyPartPath()
		{
			return bodyPartPath;
		}

		public virtual ASN1ObjectIdentifier getIdentifier()
		{
			return identifier;
		}

		public virtual ASN1Encodable getContent()
		{
			return content;
		}
	}

}