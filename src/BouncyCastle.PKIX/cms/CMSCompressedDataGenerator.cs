using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using BEROctetString = org.bouncycastle.asn1.BEROctetString;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using CompressedData = org.bouncycastle.asn1.cms.CompressedData;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using OutputCompressor = org.bouncycastle.@operator.OutputCompressor;

	/// <summary>
	/// General class for generating a compressed CMS message.
	/// <para>
	/// A simple example of usage.
	/// </para>
	/// <para>
	/// <pre>
	///      CMSCompressedDataGenerator  fact = new CMSCompressedDataGenerator();
	/// 
	///      CMSCompressedData           data = fact.generate(content, new ZlibCompressor());
	/// </pre>
	/// </para>
	/// </summary>
	public class CMSCompressedDataGenerator
	{
		public const string ZLIB = "1.2.840.113549.1.9.16.3.8";

		/// <summary>
		/// base constructor
		/// </summary>
		public CMSCompressedDataGenerator()
		{
		}

		/// <summary>
		/// generate an object that contains an CMS Compressed Data
		/// </summary>
		public virtual CMSCompressedData generate(CMSTypedData content, OutputCompressor compressor)
		{
			AlgorithmIdentifier comAlgId;
			ASN1OctetString comOcts;

			try
			{
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				OutputStream zOut = compressor.getOutputStream(bOut);

				content.write(zOut);

				zOut.close();

				comAlgId = compressor.getAlgorithmIdentifier();
				comOcts = new BEROctetString(bOut.toByteArray());
			}
			catch (IOException e)
			{
				throw new CMSException("exception encoding data.", e);
			}

			ContentInfo comContent = new ContentInfo(content.getContentType(), comOcts);

			ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers_Fields.compressedData, new CompressedData(comAlgId, comContent));

			return new CMSCompressedData(contentInfo);
		}
	}

}