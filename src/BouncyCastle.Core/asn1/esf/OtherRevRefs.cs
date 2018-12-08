using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.esf
{


	/// <summary>
	/// <pre>
	/// OtherRevRefs ::= SEQUENCE {
	///   otherRevRefType OtherRevRefType,
	///   otherRevRefs ANY DEFINED BY otherRevRefType
	/// }
	/// 
	/// OtherRevRefType ::= OBJECT IDENTIFIER
	/// </pre>
	/// </summary>
	public class OtherRevRefs : ASN1Object
	{

		private ASN1ObjectIdentifier otherRevRefType;
		private ASN1Encodable otherRevRefs;

		public static OtherRevRefs getInstance(object obj)
		{
			if (obj is OtherRevRefs)
			{
				return (OtherRevRefs)obj;
			}
			else if (obj != null)
			{
				return new OtherRevRefs(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private OtherRevRefs(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}
			this.otherRevRefType = new ASN1ObjectIdentifier(((ASN1ObjectIdentifier)seq.getObjectAt(0)).getId());
			try
			{
				this.otherRevRefs = ASN1Primitive.fromByteArray(seq.getObjectAt(1).toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER));
			}
			catch (IOException)
			{
				throw new IllegalStateException();
			}
		}

		public OtherRevRefs(ASN1ObjectIdentifier otherRevRefType, ASN1Encodable otherRevRefs)
		{
			this.otherRevRefType = otherRevRefType;
			this.otherRevRefs = otherRevRefs;
		}

		public virtual ASN1ObjectIdentifier getOtherRevRefType()
		{
			return this.otherRevRefType;
		}

		public virtual ASN1Encodable getOtherRevRefs()
		{
			return this.otherRevRefs;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(this.otherRevRefType);
			v.add(this.otherRevRefs);
			return new DERSequence(v);
		}
	}

}