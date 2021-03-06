﻿using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.1">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <pre>
	/// RecipientIdentifier ::= CHOICE {
	///     issuerAndSerialNumber IssuerAndSerialNumber,
	///     subjectKeyIdentifier [0] SubjectKeyIdentifier 
	/// }
	/// 
	/// SubjectKeyIdentifier ::= OCTET STRING
	/// </pre>
	/// </summary>
	public class RecipientIdentifier : ASN1Object, ASN1Choice
	{
		private ASN1Encodable id;

		public RecipientIdentifier(IssuerAndSerialNumber id)
		{
			this.id = id;
		}

		public RecipientIdentifier(ASN1OctetString id)
		{
			this.id = new DERTaggedObject(false, 0, id);
		}

		public RecipientIdentifier(ASN1Primitive id)
		{
			this.id = id;
		}

		/// <summary>
		/// Return a RecipientIdentifier object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="RecipientIdentifier"/> object
		/// <li> <seealso cref="IssuerAndSerialNumber"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1OctetString#getInstance(java.lang.Object) ASN1OctetString"/> input formats (OctetString, byte[]) with value of KeyIdentifier in DER form
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Primitive ASN1Primitive"/> for RecipientIdentifier constructor
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static RecipientIdentifier getInstance(object o)
		{
			if (o == null || o is RecipientIdentifier)
			{
				return (RecipientIdentifier)o;
			}

			if (o is IssuerAndSerialNumber)
			{
				return new RecipientIdentifier((IssuerAndSerialNumber)o);
			}

			if (o is ASN1OctetString)
			{
				return new RecipientIdentifier((ASN1OctetString)o);
			}

			if (o is ASN1Primitive)
			{
				return new RecipientIdentifier((ASN1Primitive)o);
			}

			throw new IllegalArgumentException("Illegal object in RecipientIdentifier: " + o.GetType().getName());
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

			return IssuerAndSerialNumber.getInstance(id);
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