using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.cms
{

	
	/// <summary>
	/// Parser for <a href="http://tools.ietf.org/html/rfc5652#section-6.1">RFC 5652</a> EncryptedContentInfo object.
	/// <para>
	/// <pre>
	/// EncryptedContentInfo ::= SEQUENCE {
	///     contentType ContentType,
	///     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
	///     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL 
	/// }
	/// </pre>
	/// </para>
	/// </summary>
	public class EncryptedContentInfoParser
	{
		private ASN1ObjectIdentifier _contentType;
		private AlgorithmIdentifier _contentEncryptionAlgorithm;
		private ASN1TaggedObjectParser _encryptedContent;

		public EncryptedContentInfoParser(ASN1SequenceParser seq)
		{
			_contentType = (ASN1ObjectIdentifier)seq.readObject();
			_contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.readObject().toASN1Primitive());
			_encryptedContent = (ASN1TaggedObjectParser)seq.readObject();
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return _contentType;
		}

		public virtual AlgorithmIdentifier getContentEncryptionAlgorithm()
		{
			return _contentEncryptionAlgorithm;
		}

		public virtual ASN1Encodable getEncryptedContent(int tag)
		{
			return _encryptedContent.getObjectParser(tag, false);
		}
	}

}