using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.pkcs
{


	public class ContentInfo : ASN1Object, PKCSObjectIdentifiers
	{
		private ASN1ObjectIdentifier contentType;
		private ASN1Encodable content;
		private bool isBer = true;

		public static ContentInfo getInstance(object obj)
		{
			if (obj is ContentInfo)
			{
				return (ContentInfo)obj;
			}

			if (obj != null)
			{
				return new ContentInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private ContentInfo(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			contentType = (ASN1ObjectIdentifier)e.nextElement();

			if (e.hasMoreElements())
			{
				content = ((ASN1TaggedObject)e.nextElement()).getObject();
			}

			isBer = seq is BERSequence;
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
		/// <pre>
		/// ContentInfo ::= SEQUENCE {
		///          contentType ContentType,
		///          content
		///          [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(contentType);

			if (content != null)
			{
				v.add(new BERTaggedObject(true, 0, content));
			}

			if (isBer)
			{
				return new BERSequence(v);
			}
			else
			{
				return new DLSequence(v);
			}
		}
	}

}