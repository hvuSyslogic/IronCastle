namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using KEKRecipientInfo = org.bouncycastle.asn1.cms.KEKRecipientInfo;
	using KeyAgreeRecipientInfo = org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
	using KeyTransRecipientInfo = org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
	using PasswordRecipientInfo = org.bouncycastle.asn1.cms.PasswordRecipientInfo;
	using RecipientInfo = org.bouncycastle.asn1.cms.RecipientInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	public class CMSEnvelopedHelper
	{
		internal static RecipientInformationStore buildRecipientInformationStore(ASN1Set recipientInfos, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable)
		{
			return buildRecipientInformationStore(recipientInfos, messageAlgorithm, secureReadable, null);
		}

		internal static RecipientInformationStore buildRecipientInformationStore(ASN1Set recipientInfos, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable, AuthAttributesProvider additionalData)
		{
			List infos = new ArrayList();
			for (int i = 0; i != recipientInfos.size(); i++)
			{
				RecipientInfo info = RecipientInfo.getInstance(recipientInfos.getObjectAt(i));

				readRecipientInfo(infos, info, messageAlgorithm, secureReadable, additionalData);
			}
			return new RecipientInformationStore(infos);
		}

		private static void readRecipientInfo(List infos, RecipientInfo info, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable, AuthAttributesProvider additionalData)
		{
			ASN1Encodable recipInfo = info.getInfo();
			if (recipInfo is KeyTransRecipientInfo)
			{
				infos.add(new KeyTransRecipientInformation((KeyTransRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData));
			}
			else if (recipInfo is KEKRecipientInfo)
			{
				infos.add(new KEKRecipientInformation((KEKRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData));
			}
			else if (recipInfo is KeyAgreeRecipientInfo)
			{
				KeyAgreeRecipientInformation.readRecipientInfo(infos, (KeyAgreeRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData);
			}
			else if (recipInfo is PasswordRecipientInfo)
			{
				infos.add(new PasswordRecipientInformation((PasswordRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData));
			}
		}

		public class CMSDigestAuthenticatedSecureReadable : CMSSecureReadable
		{
			internal DigestCalculator digestCalculator;
			internal CMSReadable readable;

			public CMSDigestAuthenticatedSecureReadable(DigestCalculator digestCalculator, CMSReadable readable)
			{
				this.digestCalculator = digestCalculator;
				this.readable = readable;
			}

			public virtual InputStream getInputStream()
			{
				return new FilterInputStreamAnonymousInnerClass(this, readable.getInputStream());
			}

			public class FilterInputStreamAnonymousInnerClass : FilterInputStream
			{
				private readonly CMSDigestAuthenticatedSecureReadable outerInstance;

				public FilterInputStreamAnonymousInnerClass(CMSDigestAuthenticatedSecureReadable outerInstance, InputStream getInputStream) : base(getInputStream)
				{
					this.outerInstance = outerInstance;
				}

				public int read()
				{
					int b = @in.read();

					if (b >= 0)
					{
						outerInstance.digestCalculator.getOutputStream().write(b);
					}

					return b;
				}

				public int read(byte[] inBuf, int inOff, int inLen)
				{
					int n = @in.read(inBuf, inOff, inLen);

					if (n >= 0)
					{
						outerInstance.digestCalculator.getOutputStream().write(inBuf, inOff, n);
					}

					return n;
				}
			}

			public virtual byte[] getDigest()
			{
				return digestCalculator.getDigest();
			}
		}

		public class CMSAuthenticatedSecureReadable : CMSSecureReadable
		{
			internal AlgorithmIdentifier algorithm;
			internal CMSReadable readable;

			public CMSAuthenticatedSecureReadable(AlgorithmIdentifier algorithm, CMSReadable readable)
			{
				this.algorithm = algorithm;
				this.readable = readable;
			}

			public virtual InputStream getInputStream()
			{
				return readable.getInputStream();
			}

		}

		public class CMSEnvelopedSecureReadable : CMSSecureReadable
		{
			internal AlgorithmIdentifier algorithm;
			internal CMSReadable readable;

			public CMSEnvelopedSecureReadable(AlgorithmIdentifier algorithm, CMSReadable readable)
			{
				this.algorithm = algorithm;
				this.readable = readable;
			}

			public virtual InputStream getInputStream()
			{
				return readable.getInputStream();
			}

		}
	}

}