using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <pre>
	/// OriginatorIdentifierOrKey ::= CHOICE {
	///     issuerAndSerialNumber IssuerAndSerialNumber,
	///     subjectKeyIdentifier [0] SubjectKeyIdentifier,
	///     originatorKey [1] OriginatorPublicKey 
	/// }
	/// 
	/// SubjectKeyIdentifier ::= OCTET STRING
	/// </pre>
	/// </summary>
	public class OriginatorIdentifierOrKey : ASN1Object, ASN1Choice
	{
		private ASN1Encodable id;

		public OriginatorIdentifierOrKey(IssuerAndSerialNumber id)
		{
			this.id = id;
		}

		/// @deprecated use version taking a SubjectKeyIdentifier 
		public OriginatorIdentifierOrKey(ASN1OctetString id) : this(new SubjectKeyIdentifier(id.getOctets()))
		{
		}

		public OriginatorIdentifierOrKey(SubjectKeyIdentifier id)
		{
			this.id = new DERTaggedObject(false, 0, id);
		}

		public OriginatorIdentifierOrKey(OriginatorPublicKey id)
		{
			this.id = new DERTaggedObject(false, 1, id);
		}

		/// @deprecated use more specific version 
		public OriginatorIdentifierOrKey(ASN1Primitive id)
		{
			this.id = id;
		}

		/// <summary>
		/// Return an OriginatorIdentifierOrKey object from a tagged object.
		/// </summary>
		/// <param name="o"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static OriginatorIdentifierOrKey getInstance(ASN1TaggedObject o, bool @explicit)
		{
			if (!@explicit)
			{
				throw new IllegalArgumentException("Can't implicitly tag OriginatorIdentifierOrKey");
			}

			return getInstance(o.getObject());
		}

		/// <summary>
		/// Return an OriginatorIdentifierOrKey object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="OriginatorIdentifierOrKey"/> object
		/// <li> <seealso cref="IssuerAndSerialNumber"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1TaggedObject#getInstance(java.lang.Object) ASN1TaggedObject"/> input formats with IssuerAndSerialNumber structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static OriginatorIdentifierOrKey getInstance(object o)
		{
			if (o == null || o is OriginatorIdentifierOrKey)
			{
				return (OriginatorIdentifierOrKey)o;
			}

			if (o is IssuerAndSerialNumber || o is ASN1Sequence)
			{
				return new OriginatorIdentifierOrKey(IssuerAndSerialNumber.getInstance(o));
			}

			if (o is ASN1TaggedObject)
			{
				ASN1TaggedObject tagged = (ASN1TaggedObject)o;

				if (tagged.getTagNo() == 0)
				{
					return new OriginatorIdentifierOrKey(SubjectKeyIdentifier.getInstance(tagged, false));
				}
				else if (tagged.getTagNo() == 1)
				{
					return new OriginatorIdentifierOrKey(OriginatorPublicKey.getInstance(tagged, false));
				}
			}

			throw new IllegalArgumentException("Invalid OriginatorIdentifierOrKey: " + o.GetType().getName());
		}

		public virtual ASN1Encodable getId()
		{
			return id;
		}

		public virtual IssuerAndSerialNumber getIssuerAndSerialNumber()
		{
			if (id is IssuerAndSerialNumber)
			{
				return (IssuerAndSerialNumber)id;
			}

			return null;
		}

		public virtual SubjectKeyIdentifier getSubjectKeyIdentifier()
		{
			if (id is ASN1TaggedObject && ((ASN1TaggedObject)id).getTagNo() == 0)
			{
				return SubjectKeyIdentifier.getInstance((ASN1TaggedObject)id, false);
			}

			return null;
		}

		public virtual OriginatorPublicKey getOriginatorKey()
		{
			if (id is ASN1TaggedObject && ((ASN1TaggedObject)id).getTagNo() == 1)
			{
				return OriginatorPublicKey.getInstance((ASN1TaggedObject)id, false);
			}

			return null;
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