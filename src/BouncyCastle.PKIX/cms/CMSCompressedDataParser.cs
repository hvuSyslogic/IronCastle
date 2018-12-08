using org.bouncycastle.asn1;

namespace org.bouncycastle.cms
{

	using ASN1OctetStringParser = org.bouncycastle.asn1.ASN1OctetStringParser;
	using ASN1SequenceParser = org.bouncycastle.asn1.ASN1SequenceParser;
	using BERTags = org.bouncycastle.asn1.BERTags;
	using CompressedDataParser = org.bouncycastle.asn1.cms.CompressedDataParser;
	using ContentInfoParser = org.bouncycastle.asn1.cms.ContentInfoParser;
	using InputExpander = org.bouncycastle.@operator.InputExpander;
	using InputExpanderProvider = org.bouncycastle.@operator.InputExpanderProvider;

	/// <summary>
	/// Class for reading a CMS Compressed Data stream.
	/// <pre>
	///     CMSCompressedDataParser cp = new CMSCompressedDataParser(inputStream);
	/// 
	///     process(cp.getContent(new ZlibExpanderProvider()).getContentStream());
	/// </pre>
	///  Note: this class does not introduce buffering - if you are processing large files you should create
	///  the parser with:
	///  <pre>
	///      CMSCompressedDataParser     ep = new CMSCompressedDataParser(new BufferedInputStream(inputStream, bufSize));
	///  </pre>
	///  where bufSize is a suitably large buffer size.
	/// </summary>
	public class CMSCompressedDataParser : CMSContentInfoParser
	{
		public CMSCompressedDataParser(byte[] compressedData) : this(new ByteArrayInputStream(compressedData))
		{
		}

		public CMSCompressedDataParser(InputStream compressedData) : base(compressedData)
		{
		}

		/// <summary>
		/// Return a typed stream which will allow the reading of the compressed content in
		/// expanded form.
		/// </summary>
		/// <param name="expanderProvider"> a provider of expander algorithm implementations. </param>
		/// <returns> a type stream which will yield the un-compressed content. </returns>
		/// <exception cref="CMSException"> if there is an exception parsing the CompressedData object. </exception>
		public virtual CMSTypedStream getContent(InputExpanderProvider expanderProvider)
		{
			try
			{
				CompressedDataParser comData = new CompressedDataParser((ASN1SequenceParser)_contentInfo.getContent(BERTags_Fields.SEQUENCE));
				ContentInfoParser content = comData.getEncapContentInfo();
				InputExpander expander = expanderProvider.get(comData.getCompressionAlgorithmIdentifier());

				ASN1OctetStringParser bytes = (ASN1OctetStringParser)content.getContent(BERTags_Fields.OCTET_STRING);

				return new CMSTypedStream(content.getContentType().getId(), expander.getInputStream(bytes.getOctetStream()));
			}
			catch (IOException e)
			{
				throw new CMSException("IOException reading compressed content.", e);
			}
		}
	}

}