namespace org.bouncycastle.tsp.cms
{

	using ASN1Boolean = org.bouncycastle.asn1.ASN1Boolean;
	using DERIA5String = org.bouncycastle.asn1.DERIA5String;
	using DERUTF8String = org.bouncycastle.asn1.DERUTF8String;
	using Attributes = org.bouncycastle.asn1.cms.Attributes;
	using MetaData = org.bouncycastle.asn1.cms.MetaData;
	using CMSException = org.bouncycastle.cms.CMSException;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	public class CMSTimeStampedGenerator
	{
		protected internal MetaData metaData;
		protected internal URI dataUri;

		/// <summary>
		/// Set the dataURI to be included in message.
		/// </summary>
		/// <param name="dataUri"> URI for the data the initial message imprint digest is based on. </param>
		public virtual void setDataUri(URI dataUri)
		{
			this.dataUri = dataUri;
		}

		/// <summary>
		/// Set the MetaData for the generated message.
		/// </summary>
		/// <param name="hashProtected"> true if the MetaData should be included in first imprint calculation, false otherwise. </param>
		/// <param name="fileName"> optional file name, may be null. </param>
		/// <param name="mediaType"> optional media type, may be null. </param>
		public virtual void setMetaData(bool hashProtected, string fileName, string mediaType)
		{
			setMetaData(hashProtected, fileName, mediaType, null);
		}

		/// <summary>
		/// Set the MetaData for the generated message.
		/// </summary>
		/// <param name="hashProtected"> true if the MetaData should be included in first imprint calculation, false otherwise. </param>
		/// <param name="fileName"> optional file name, may be null. </param>
		/// <param name="mediaType"> optional media type, may be null. </param>
		/// <param name="attributes"> optional attributes, may be null. </param>
		public virtual void setMetaData(bool hashProtected, string fileName, string mediaType, Attributes attributes)
		{
			DERUTF8String asn1FileName = null;

			if (!string.ReferenceEquals(fileName, null))
			{
				asn1FileName = new DERUTF8String(fileName);
			}

			DERIA5String asn1MediaType = null;

			if (!string.ReferenceEquals(mediaType, null))
			{
				asn1MediaType = new DERIA5String(mediaType);
			}

			setMetaData(hashProtected, asn1FileName, asn1MediaType, attributes);
		}

		private void setMetaData(bool hashProtected, DERUTF8String fileName, DERIA5String mediaType, Attributes attributes)
		{
			this.metaData = new MetaData(ASN1Boolean.getInstance(hashProtected), fileName, mediaType, attributes);
		}

		/// <summary>
		/// Initialise the passed in calculator with the MetaData for this message, if it is
		/// required as part of the initial message imprint calculation. After initialisation the
		/// calculator can then be used to calculate the initial message imprint digest for the first
		/// timestamp.
		/// </summary>
		/// <param name="calculator"> the digest calculator to be initialised. </param>
		/// <exception cref="CMSException"> if the MetaData is required and cannot be processed </exception>
		public virtual void initialiseMessageImprintDigestCalculator(DigestCalculator calculator)
		{
			MetaDataUtil util = new MetaDataUtil(metaData);

			util.initialiseMessageImprintDigestCalculator(calculator);
		}
	}

}