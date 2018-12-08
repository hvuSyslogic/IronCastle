using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-5.3">RFC 5652</a>:
	/// Identify who signed the containing <seealso cref="SignerInfo"/> object.
	/// <para>
	/// The certificates referred to by this are at containing <seealso cref="SignedData"/> structure.
	/// </para>
	/// <para>
	/// <pre>
	/// SignerIdentifier ::= CHOICE {
	///     issuerAndSerialNumber IssuerAndSerialNumber,
	///     subjectKeyIdentifier [0] SubjectKeyIdentifier 
	/// }
	/// 
	/// SubjectKeyIdentifier ::= OCTET STRING
	/// </pre>
	/// </para>
	/// </summary>
	public class SignerIdentifier : ASN1Object, ASN1Choice
	{
		private ASN1Encodable id;

		public SignerIdentifier(IssuerAndSerialNumber id)
		{
			this.id = id;
		}

		public SignerIdentifier(ASN1OctetString id)
		{
			this.id = new DERTaggedObject(false, 0, id);
		}

		public SignerIdentifier(ASN1Primitive id)
		{
			this.id = id;
		}

		/// <summary>
		/// Return a SignerIdentifier object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="SignerIdentifier"/> object
		/// <li> <seealso cref="IssuerAndSerialNumber"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1OctetString#getInstance(java.lang.Object) ASN1OctetString"/> input formats with SignerIdentifier structure inside
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Primitive ASN1Primitive"/> for SignerIdentifier constructor.
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static SignerIdentifier getInstance(object o)
		{
			if (o == null || o is SignerIdentifier)
			{
				return (SignerIdentifier)o;
			}

			if (o is IssuerAndSerialNumber)
			{
				return new SignerIdentifier((IssuerAndSerialNumber)o);
			}

			if (o is ASN1OctetString)
			{
				return new SignerIdentifier((ASN1OctetString)o);
			}

			if (o is ASN1Primitive)
			{
				return new SignerIdentifier((ASN1Primitive)o);
			}

			throw new IllegalArgumentException("Illegal object in SignerIdentifier: " + o.GetType().getName());
		}

		public virtual bool isTagged()
		{
			return (id is ASN1TaggedObject);
		}

		public virtual ASN1Encodable getId()
		{
			if (id is ASN1TaggedObject)
			{
				return ASN1OctetString.getInstance((ASN1TaggedObject)id, false);
			}

			return id;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return id.toASN1Primitive();
		}
	}

}