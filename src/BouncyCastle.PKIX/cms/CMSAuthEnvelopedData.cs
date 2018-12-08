namespace org.bouncycastle.cms
{

	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using AuthEnvelopedData = org.bouncycastle.asn1.cms.AuthEnvelopedData;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using EncryptedContentInfo = org.bouncycastle.asn1.cms.EncryptedContentInfo;
	using OriginatorInfo = org.bouncycastle.asn1.cms.OriginatorInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// containing class for an CMS AuthEnveloped Data object
	/// </summary>
	public class CMSAuthEnvelopedData
	{
		internal RecipientInformationStore recipientInfoStore;
		internal ContentInfo contentInfo;

		private OriginatorInfo originator;
		private AlgorithmIdentifier authEncAlg;
		private ASN1Set authAttrs;
		private byte[] mac;
		private ASN1Set unauthAttrs;

		public CMSAuthEnvelopedData(byte[] authEnvData) : this(CMSUtils.readContentInfo(authEnvData))
		{
		}

		public CMSAuthEnvelopedData(InputStream authEnvData) : this(CMSUtils.readContentInfo(authEnvData))
		{
		}

		public CMSAuthEnvelopedData(ContentInfo contentInfo)
		{
			this.contentInfo = contentInfo;

			AuthEnvelopedData authEnvData = AuthEnvelopedData.getInstance(contentInfo.getContent());

			this.originator = authEnvData.getOriginatorInfo();

			//
			// read the recipients
			//
			ASN1Set recipientInfos = authEnvData.getRecipientInfos();

			//
			// read the auth-encrypted content info
			//
			EncryptedContentInfo authEncInfo = authEnvData.getAuthEncryptedContentInfo();
			this.authEncAlg = authEncInfo.getContentEncryptionAlgorithm();
	//        final CMSProcessable processable = new CMSProcessableByteArray(
	//            authEncInfo.getEncryptedContent().getOctets());
			CMSSecureReadable secureReadable = new CMSSecureReadableAnonymousInnerClass(this);

			//
			// build the RecipientInformationStore
			//
			this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, this.authEncAlg, secureReadable);

			// FIXME These need to be passed to the AEAD cipher as AAD (Additional Authenticated Data)
			this.authAttrs = authEnvData.getAuthAttrs();
			this.mac = authEnvData.getMac().getOctets();
			this.unauthAttrs = authEnvData.getUnauthAttrs();
		}

		public class CMSSecureReadableAnonymousInnerClass : CMSSecureReadable
		{
			private readonly CMSAuthEnvelopedData outerInstance;

			public CMSSecureReadableAnonymousInnerClass(CMSAuthEnvelopedData outerInstance)
			{
				this.outerInstance = outerInstance;
			}


			public InputStream getInputStream()
			{
				return null;
			}
		}
	}

}