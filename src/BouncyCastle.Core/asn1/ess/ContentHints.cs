namespace org.bouncycastle.asn1.ess
{

	public class ContentHints : ASN1Object
	{
		private DERUTF8String contentDescription;
		private ASN1ObjectIdentifier contentType;

		public static ContentHints getInstance(object o)
		{
			if (o is ContentHints)
			{
				return (ContentHints)o;
			}
			else if (o != null)
			{
				return new ContentHints(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		/// <summary>
		/// constructor
		/// </summary>
		private ContentHints(ASN1Sequence seq)
		{
			ASN1Encodable field = seq.getObjectAt(0);
			if (field.toASN1Primitive() is DERUTF8String)
			{
				contentDescription = DERUTF8String.getInstance(field);
				contentType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
			}
			else
			{
				contentType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
			}
		}

		public ContentHints(ASN1ObjectIdentifier contentType)
		{
			this.contentType = contentType;
			this.contentDescription = null;
		}

		public ContentHints(ASN1ObjectIdentifier contentType, DERUTF8String contentDescription)
		{
			this.contentType = contentType;
			this.contentDescription = contentDescription;
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return contentType;
		}

		public virtual DERUTF8String getContentDescription()
		{
			return contentDescription;
		}

		/// <summary>
		/// <pre>
		/// ContentHints ::= SEQUENCE {
		///   contentDescription UTF8String (SIZE (1..MAX)) OPTIONAL,
		///   contentType ContentType }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (contentDescription != null)
			{
				v.add(contentDescription);
			}

			v.add(contentType);

			return new DERSequence(v);
		}
	}

}