using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-3">RFC 5652</a> ContentInfo, and 
	/// <a href="http://tools.ietf.org/html/rfc5652#section-5.2">RFC 5652</a> EncapsulatedContentInfo objects.
	/// 
	/// <pre>
	/// ContentInfo ::= SEQUENCE {
	///     contentType ContentType,
	///     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
	/// }
	/// 
	/// EncapsulatedContentInfo ::= SEQUENCE {
	///     eContentType ContentType,
	///     eContent [0] EXPLICIT OCTET STRING OPTIONAL
	/// }
	/// </pre>
	/// </summary>
	public class ContentInfo : ASN1Object, CMSObjectIdentifiers
	{
		private ASN1ObjectIdentifier contentType;
		private ASN1Encodable content;

		/// <summary>
		/// Return an ContentInfo object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="ContentInfo"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with ContentInfo structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static ContentInfo getInstance(object obj)
		{
			if (obj is ContentInfo)
			{
				return (ContentInfo)obj;
			}
			else if (obj != null)
			{
				return new ContentInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static ContentInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// @deprecated use getInstance() 
		public ContentInfo(ASN1Sequence seq)
		{
			if (seq.size() < 1 || seq.size() > 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			contentType = (ASN1ObjectIdentifier)seq.getObjectAt(0);

			if (seq.size() > 1)
			{
				ASN1TaggedObject tagged = (ASN1TaggedObject)seq.getObjectAt(1);
				if (!tagged.isExplicit() || tagged.getTagNo() != 0)
				{
					throw new IllegalArgumentException("Bad tag for 'content'");
				}

				content = tagged.getObject();
			}
		}

		public ContentInfo(ASN1ObjectIdentifier contentType, ASN1Encodable content)
		{
			this.contentType = contentType;
			this.content = content;
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return contentType;
		}

		public virtual ASN1Encodable getContent()
		{
			return content;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(contentType);

			if (content != null)
			{
				v.add(new BERTaggedObject(0, content));
			}

			return new BERSequence(v);
		}
	}

}