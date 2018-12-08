namespace org.bouncycastle.asn1.cms
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// Parser of <a href="http://tools.ietf.org/html/rfc3274">RFC 3274</a> <seealso cref="CompressedData"/> object.
	/// <para>
	/// <pre>
	/// CompressedData ::= SEQUENCE {
	///     version CMSVersion,
	///     compressionAlgorithm CompressionAlgorithmIdentifier,
	///     encapContentInfo EncapsulatedContentInfo
	/// }
	/// </pre>
	/// </para>
	/// </summary>
	public class CompressedDataParser
	{
		private ASN1Integer _version;
		private AlgorithmIdentifier _compressionAlgorithm;
		private ContentInfoParser _encapContentInfo;

		public CompressedDataParser(ASN1SequenceParser seq)
		{
			this._version = (ASN1Integer)seq.readObject();
			this._compressionAlgorithm = AlgorithmIdentifier.getInstance(seq.readObject().toASN1Primitive());
			this._encapContentInfo = new ContentInfoParser((ASN1SequenceParser)seq.readObject());
		}

		public virtual ASN1Integer getVersion()
		{
			return _version;
		}

		public virtual AlgorithmIdentifier getCompressionAlgorithmIdentifier()
		{
			return _compressionAlgorithm;
		}

		public virtual ContentInfoParser getEncapContentInfo()
		{
			return _encapContentInfo;
		}
	}

}