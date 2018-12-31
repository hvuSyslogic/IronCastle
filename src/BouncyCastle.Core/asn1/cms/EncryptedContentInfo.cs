using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	
	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.1">RFC 5652</a> EncryptedContentInfo object.
	/// 
	/// <pre>
	/// EncryptedContentInfo ::= SEQUENCE {
	///     contentType ContentType,
	///     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
	///     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL 
	/// }
	/// </pre>
	/// </summary>
	public class EncryptedContentInfo : ASN1Object
	{
		private ASN1ObjectIdentifier contentType;
		private AlgorithmIdentifier contentEncryptionAlgorithm;
		private ASN1OctetString encryptedContent;

		public EncryptedContentInfo(ASN1ObjectIdentifier contentType, AlgorithmIdentifier contentEncryptionAlgorithm, ASN1OctetString encryptedContent)
		{
			this.contentType = contentType;
			this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
			this.encryptedContent = encryptedContent;
		}

		private EncryptedContentInfo(ASN1Sequence seq)
		{
			if (seq.size() < 2)
			{
				throw new IllegalArgumentException("Truncated Sequence Found");
			}

			contentType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
			contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			if (seq.size() > 2)
			{
				encryptedContent = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(2), false);
			}
		}

		/// <summary>
		/// Return an EncryptedContentInfo object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="EncryptedContentInfo"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static EncryptedContentInfo getInstance(object obj)
		{
			if (obj is EncryptedContentInfo)
			{
				return (EncryptedContentInfo)obj;
			}
			if (obj != null)
			{
				return new EncryptedContentInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return contentType;
		}

		public virtual AlgorithmIdentifier getContentEncryptionAlgorithm()
		{
			return contentEncryptionAlgorithm;
		}

		public virtual ASN1OctetString getEncryptedContent()
		{
			return encryptedContent;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(contentType);
			v.add(contentEncryptionAlgorithm);

			if (encryptedContent != null)
			{
				v.add(new BERTaggedObject(false, 0, encryptedContent));
			}

			return new BERSequence(v);
		}
	}

}