using System;

namespace org.bouncycastle.cms
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using DigestedData = org.bouncycastle.asn1.cms.DigestedData;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Arrays = org.bouncycastle.util.Arrays;
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// containing class for an CMS Digested Data object
	/// <pre>
	///     CMSDigestedData cd = new CMSDigestedData(inputStream);
	/// 
	/// 
	///     process(cd.getContent());
	/// </pre>
	/// </summary>
	public class CMSDigestedData : Encodable
	{
		private ContentInfo contentInfo;
		private DigestedData digestedData;

		public CMSDigestedData(byte[] compressedData) : this(CMSUtils.readContentInfo(compressedData))
		{
		}

		public CMSDigestedData(InputStream compressedData) : this(CMSUtils.readContentInfo(compressedData))
		{
		}

		public CMSDigestedData(ContentInfo contentInfo)
		{
			this.contentInfo = contentInfo;

			try
			{
				this.digestedData = DigestedData.getInstance(contentInfo.getContent());
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

		public virtual AlgorithmIdentifier getDigestAlgorithm()
		{
			return digestedData.getDigestAlgorithm();
		}

		/// <summary>
		/// Return the digested content
		/// </summary>
		/// <returns> the digested content </returns>
		/// <exception cref="CMSException"> if there is an exception un-compressing the data. </exception>
		public virtual CMSProcessable getDigestedContent()
		{
			ContentInfo content = digestedData.getEncapContentInfo();

			try
			{
				return new CMSProcessableByteArray(content.getContentType(), ((ASN1OctetString)content.getContent()).getOctets());
			}
			catch (Exception e)
			{
				throw new CMSException("exception reading digested stream.", e);
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

		public virtual bool verify(DigestCalculatorProvider calculatorProvider)
		{
			try
			{
				ContentInfo content = digestedData.getEncapContentInfo();
				DigestCalculator calc = calculatorProvider.get(digestedData.getDigestAlgorithm());

				OutputStream dOut = calc.getOutputStream();

				dOut.write(((ASN1OctetString)content.getContent()).getOctets());

				return Arrays.areEqual(digestedData.getDigest(), calc.getDigest());
			}
			catch (OperatorCreationException e)
			{
				throw new CMSException("unable to create digest calculator: " + e.Message, e);
			}
			catch (IOException e)
			{
				throw new CMSException("unable process content: " + e.Message, e);
			}
		}
	}

}