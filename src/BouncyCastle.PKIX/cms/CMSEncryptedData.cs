using System;

namespace org.bouncycastle.cms
{

	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using EncryptedContentInfo = org.bouncycastle.asn1.cms.EncryptedContentInfo;
	using EncryptedData = org.bouncycastle.asn1.cms.EncryptedData;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;
	using InputDecryptorProvider = org.bouncycastle.@operator.InputDecryptorProvider;

	public class CMSEncryptedData
	{
		private ContentInfo contentInfo;
		private EncryptedData encryptedData;

		public CMSEncryptedData(ContentInfo contentInfo)
		{
			this.contentInfo = contentInfo;

			this.encryptedData = EncryptedData.getInstance(contentInfo.getContent());
		}

		public virtual byte[] getContent(InputDecryptorProvider inputDecryptorProvider)
		{
			try
			{
				return CMSUtils.streamToByteArray(getContentStream(inputDecryptorProvider).getContentStream());
			}
			catch (IOException e)
			{
				throw new CMSException("unable to parse internal stream: " + e.Message, e);
			}
		}

		public virtual CMSTypedStream getContentStream(InputDecryptorProvider inputDecryptorProvider)
		{
			try
			{
				EncryptedContentInfo encContentInfo = encryptedData.getEncryptedContentInfo();
				InputDecryptor decrytor = inputDecryptorProvider.get(encContentInfo.getContentEncryptionAlgorithm());

				ByteArrayInputStream encIn = new ByteArrayInputStream(encContentInfo.getEncryptedContent().getOctets());

				return new CMSTypedStream(encContentInfo.getContentType(), decrytor.getInputStream(encIn));
			}
			catch (Exception e)
			{
				throw new CMSException("unable to create stream: " + e.Message, e);
			}
		}

		/// <summary>
		/// return the ContentInfo
		/// </summary>
		public virtual ContentInfo toASN1Structure()
		{
			return contentInfo;
		}
	}

}