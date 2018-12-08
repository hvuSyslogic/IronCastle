using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.pkcs
{

	public class Attribute : ASN1Object
	{
		private ASN1ObjectIdentifier attrType;
		private ASN1Set attrValues;

		/// <summary>
		/// return an Attribute object from the given object.
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static Attribute getInstance(object o)
		{
			if (o == null || o is Attribute)
			{
				return (Attribute)o;
			}

			if (o is ASN1Sequence)
			{
				return new Attribute((ASN1Sequence)o);
			}

			throw new IllegalArgumentException("unknown object in factory: " + o.GetType().getName());
		}

		public Attribute(ASN1Sequence seq)
		{
			attrType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
			attrValues = (ASN1Set)seq.getObjectAt(1);
		}

		public Attribute(ASN1ObjectIdentifier attrType, ASN1Set attrValues)
		{
			this.attrType = attrType;
			this.attrValues = attrValues;
		}

		public virtual ASN1ObjectIdentifier getAttrType()
		{
			return attrType;
		}

		public virtual ASN1Set getAttrValues()
		{
			return attrValues;
		}

		public virtual ASN1Encodable[] getAttributeValues()
		{
			return attrValues.toArray();
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// Attribute ::= SEQUENCE {
		///     attrType OBJECT IDENTIFIER,
		///     attrValues SET OF AttributeValue
		/// }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(attrType);
			v.add(attrValues);

			return new DERSequence(v);
		}
	}

}