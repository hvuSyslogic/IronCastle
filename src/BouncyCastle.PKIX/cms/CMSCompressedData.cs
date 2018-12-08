namespace org.bouncycastle.cms
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using CompressedData = org.bouncycastle.asn1.cms.CompressedData;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using InputExpander = org.bouncycastle.@operator.InputExpander;
	using InputExpanderProvider = org.bouncycastle.@operator.InputExpanderProvider;
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// containing class for an CMS Compressed Data object
	/// <pre>
	///     CMSCompressedData cd = new CMSCompressedData(inputStream);
	/// 
	///     process(cd.getContent(new ZlibExpanderProvider()));
	/// </pre>
	/// </summary>
	public class CMSCompressedData : Encodable
	{
		internal ContentInfo contentInfo;
		internal CompressedData comData;

		public CMSCompressedData(byte[] compressedData) : this(CMSUtils.readContentInfo(compressedData))
		{
		}

		public CMSCompressedData(InputStream compressedData) : this(CMSUtils.readContentInfo(compressedData))
		{
		}

		public CMSCompressedData(ContentInfo contentInfo)
		{
			this.contentInfo = contentInfo;

			try
			{
				this.comData = CompressedData.getInstance(contentInfo.getContent());
			}
			catch (ClassCastException e)
			{
				throw new CMSException("Malformed content.", e);
			}
			catch (IllegalArgumentException e)
			{
				throw new CMSException("Malformed content.", e);
			}
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return contentInfo.getContentType();
		}

		/// <summary>
		/// Return the uncompressed content.
		/// </summary>
		/// <param name="expanderProvider"> a provider of expander algorithm implementations. </param>
		/// <returns> the uncompressed content </returns>
		/// <exception cref="CMSException"> if there is an exception un-compressing the data. </exception>
		public virtual byte[] getContent(InputExpanderProvider expanderProvider)
		{
			ContentInfo content = comData.getEncapContentInfo();

			ASN1OctetString bytes = (ASN1OctetString)content.getContent();
			InputExpander expander = expanderProvider.get(comData.getCompressionAlgorithmIdentifier());
			InputStream zIn = expander.getInputStream(bytes.getOctetStream());

			try
			{
				return CMSUtils.streamToByteArray(zIn);
			}
			catch (IOException e)
			{
				throw new CMSException("exception reading compressed stream.", e);
			}
		}

		/// <summary>
		/// return the ContentInfo
		/// </summary>
		public virtual ContentInfo toASN1Structure()
		{
			return contentInfo;
		}

		/// <summary>
		/// return the ASN.1 encoded representation of this object.
		/// </summary>
		public virtual byte[] getEncoded()
		{
			return contentInfo.getEncoded();
		}
	}

}