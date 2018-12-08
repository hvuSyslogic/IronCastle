namespace org.bouncycastle.asn1.cms
{


	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-3">RFC 5652</a> <seealso cref="ContentInfo"/> object parser.
	/// 
	/// <pre>
	/// ContentInfo ::= SEQUENCE {
	///     contentType ContentType,
	///     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
	/// </pre>
	/// </summary>
	public class ContentInfoParser
	{
		private ASN1ObjectIdentifier contentType;
		private ASN1TaggedObjectParser content;

		public ContentInfoParser(ASN1SequenceParser seq)
		{
			contentType = (ASN1ObjectIdentifier)seq.readObject();
			content = (ASN1TaggedObjectParser)seq.readObject();
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return contentType;
		}

		public virtual ASN1Encodable getContent(int tag)
		{
			if (content != null)
			{
				return content.getObjectParser(tag, true);
			}

			return null;
		}
	}

}