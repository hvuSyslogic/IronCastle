using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.esf
{

		

	public class SignerAttribute : ASN1Object
	{
		private object[] values;

		public static SignerAttribute getInstance(object o)
		{
			if (o is SignerAttribute)
			{
				return (SignerAttribute) o;
			}
			else if (o != null)
			{
				return new SignerAttribute(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private SignerAttribute(ASN1Sequence seq)
		{
			int index = 0;
			values = new object[seq.size()];

			for (Enumeration e = seq.getObjects(); e.hasMoreElements();)
			{
				ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(e.nextElement());

				if (taggedObject.getTagNo() == 0)
				{
					ASN1Sequence attrs = ASN1Sequence.getInstance(taggedObject, true);
					Attribute[] attributes = new Attribute[attrs.size()];

					for (int i = 0; i != attributes.Length; i++)
					{
						attributes[i] = Attribute.getInstance(attrs.getObjectAt(i));
					}
					values[index] = attributes;
				}
				else if (taggedObject.getTagNo() == 1)
				{
					values[index] = AttributeCertificate.getInstance(ASN1Sequence.getInstance(taggedObject, true));
				}
				else
				{
					throw new IllegalArgumentException("illegal tag: " + taggedObject.getTagNo());
				}
				index++;
			}
		}

		public SignerAttribute(Attribute[] claimedAttributes)
		{
			this.values = new object[1];
			this.values[0] = claimedAttributes;
		}

		public SignerAttribute(AttributeCertificate certifiedAttributes)
		{
			this.values = new object[1];
			this.values[0] = certifiedAttributes;
		}

		/// <summary>
		/// Return the sequence of choices - the array elements will either be of
		/// type Attribute[] or AttributeCertificate depending on what tag was used.
		/// </summary>
		/// <returns> array of choices. </returns>
		public virtual object[] getValues()
		{
			object[] rv = new object[values.Length];

			JavaSystem.arraycopy(values, 0, rv, 0, rv.Length);

			return rv;
		}

		/// 
		/// <summary>
		/// <pre>
		///  SignerAttribute ::= SEQUENCE OF CHOICE {
		///      claimedAttributes   [0] ClaimedAttributes,
		///      certifiedAttributes [1] CertifiedAttributes }
		/// 
		///  ClaimedAttributes ::= SEQUENCE OF Attribute
		///  CertifiedAttributes ::= AttributeCertificate -- as defined in RFC 3281: see clause 4.1.
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			for (int i = 0; i != values.Length; i++)
			{
				if (values[i] is Attribute[])
				{
					v.add(new DERTaggedObject(0, new DERSequence((Attribute[])values[i])));
				}
				else
				{
					v.add(new DERTaggedObject(1, (AttributeCertificate)values[i]));
				}
			}

			return new DERSequence(v);
		}
	}

}