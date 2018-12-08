using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652">RFC 5652</a> defines
	/// 5 "SET OF Attribute" entities with 5 different names.
	/// This is common implementation for them all:
	/// <pre>
	///   SignedAttributes      ::= SET SIZE (1..MAX) OF Attribute
	///   UnsignedAttributes    ::= SET SIZE (1..MAX) OF Attribute
	///   UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
	///   AuthAttributes        ::= SET SIZE (1..MAX) OF Attribute
	///   UnauthAttributes      ::= SET SIZE (1..MAX) OF Attribute
	/// 
	/// Attributes ::=
	///   SET SIZE(1..MAX) OF Attribute
	/// </pre>
	/// </summary>
	public class Attributes : ASN1Object
	{
		private ASN1Set attributes;

		private Attributes(ASN1Set set)
		{
			attributes = set;
		}

		public Attributes(ASN1EncodableVector v)
		{
			attributes = new DLSet(v);
		}

		/// <summary>
		/// Return an Attribute set object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="Attributes"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Set#getInstance(java.lang.Object) ASN1Set"/> input formats with Attributes structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static Attributes getInstance(object obj)
		{
			if (obj is Attributes)
			{
				return (Attributes)obj;
			}
			else if (obj != null)
			{
				return new Attributes(ASN1Set.getInstance(obj));
			}

			return null;
		}

		public virtual Attribute[] getAttributes()
		{
			Attribute[] rv = new Attribute[attributes.size()];

			for (int i = 0; i != rv.Length; i++)
			{
				rv[i] = Attribute.getInstance(attributes.getObjectAt(i));
			}

			return rv;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return attributes;
		}
	}

}