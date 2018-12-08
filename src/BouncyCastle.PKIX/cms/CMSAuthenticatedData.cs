using org.bouncycastle.asn1.cms;

using System;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using AuthenticatedData = org.bouncycastle.asn1.cms.AuthenticatedData;
	using CMSAlgorithmProtection = org.bouncycastle.asn1.cms.CMSAlgorithmProtection;
	using CMSAttributes = org.bouncycastle.asn1.cms.CMSAttributes;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Arrays = org.bouncycastle.util.Arrays;
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// containing class for an CMS Authenticated Data object
	/// </summary>
	public class CMSAuthenticatedData : Encodable
	{
		internal RecipientInformationStore recipientInfoStore;
		internal ContentInfo contentInfo;

		private AlgorithmIdentifier macAlg;
		private ASN1Set authAttrs;
		private ASN1Set unauthAttrs;
		private byte[] mac;
		private OriginatorInformation originatorInfo;

		public CMSAuthenticatedData(byte[] authData) : this(CMSUtils.readContentInfo(authData))
		{
		}

		public CMSAuthenticatedData(byte[] authData, DigestCalculatorProvider digestCalculatorProvider) : this(CMSUtils.readContentInfo(authData), digestCalculatorProvider)
		{
		}

		public CMSAuthenticatedData(InputStream authData) : this(CMSUtils.readContentInfo(authData))
		{
		}

		public CMSAuthenticatedData(InputStream authData, DigestCalculatorProvider digestCalculatorProvider) : this(CMSUtils.readContentInfo(authData), digestCalculatorProvider)
		{
		}

		public CMSAuthenticatedData(ContentInfo contentInfo) : this(contentInfo, null)
		{
		}

		public CMSAuthenticatedData(ContentInfo contentInfo, DigestCalculatorProvider digestCalculatorProvider)
		{
			this.contentInfo = contentInfo;

			AuthenticatedData authData = AuthenticatedData.getInstance(contentInfo.getContent());

			if (authData.getOriginatorInfo() != null)
			{
				this.originatorInfo = new OriginatorInformation(authData.getOriginatorInfo());
			}

			//
			// read the recipients
			//
			ASN1Set recipientInfos = authData.getRecipientInfos();

			this.macAlg = authData.getMacAlgorithm();

			this.authAttrs = authData.getAuthAttrs();
			this.mac = authData.getMac().getOctets();
			this.unauthAttrs = authData.getUnauthAttrs();

			//
			// read the authenticated content info
			//
			ContentInfo encInfo = authData.getEncapsulatedContentInfo();
			CMSReadable readable = new CMSProcessableByteArray(ASN1OctetString.getInstance(encInfo.getContent()).getOctets());

			//
			// build the RecipientInformationStore
			//
			if (authAttrs != null)
			{
				if (digestCalculatorProvider == null)
				{
					throw new CMSException("a digest calculator provider is required if authenticated attributes are present");
				}

				AttributeTable table = new AttributeTable(authAttrs);

				ASN1EncodableVector protectionAttributes = table.getAll(CMSAttributes_Fields.cmsAlgorithmProtect);
				if (protectionAttributes.size() > 1)
				{
					throw new CMSException("Only one instance of a cmsAlgorithmProtect attribute can be present");
				}

				if (protectionAttributes.size() > 0)
				{
					Attribute attr = Attribute.getInstance(protectionAttributes.get(0));
					if (attr.getAttrValues().size() != 1)
					{
						throw new CMSException("A cmsAlgorithmProtect attribute MUST contain exactly one value");
					}

					CMSAlgorithmProtection algorithmProtection = CMSAlgorithmProtection.getInstance(attr.getAttributeValues()[0]);

					if (!CMSUtils.isEquivalent(algorithmProtection.getDigestAlgorithm(), authData.getDigestAlgorithm()))
					{
						throw new CMSException("CMS Algorithm Identifier Protection check failed for digestAlgorithm");
					}

					if (!CMSUtils.isEquivalent(algorithmProtection.getMacAlgorithm(), macAlg))
					{
						throw new CMSException("CMS Algorithm Identifier Protection check failed for macAlgorithm");
					}
				}
				try
				{
					CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSDigestAuthenticatedSecureReadable(digestCalculatorProvider.get(authData.getDigestAlgorithm()), readable);

					this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, this.macAlg, secureReadable, new AuthAttributesProviderAnonymousInnerClass(this));
				}
				catch (OperatorCreationException e)
				{
					throw new CMSException("unable to create digest calculator: " + e.Message, e);
				}
			}
			else
			{
				CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSAuthenticatedSecureReadable(this.macAlg, readable);

				this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, this.macAlg, secureReadable);
			}
		}

		public class AuthAttributesProviderAnonymousInnerClass : AuthAttributesProvider
		{
			private readonly CMSAuthenticatedData outerInstance;

			public AuthAttributesProviderAnonymousInnerClass(CMSAuthenticatedData outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public ASN1Set getAuthAttributes()
			{
				return outerInstance.authAttrs;
			}
		}

		/// <summary>
		/// Return the originator information associated with this message if present.
		/// </summary>
		/// <returns> OriginatorInformation, null if not present. </returns>
		public virtual OriginatorInformation getOriginatorInfo()
		{
			return originatorInfo;
		}

		public virtual byte[] getMac()
		{
			return Arrays.clone(mac);
		}

		private byte[] encodeObj(ASN1Encodable obj)
		{
			if (obj != null)
			{
				return obj.toASN1Primitive().getEncoded();
			}

			return null;
		}

		/// <summary>
		/// Return the MAC algorithm details for the MAC associated with the data in this object.
		/// </summary>
		/// <returns> AlgorithmIdentifier representing the MAC algorithm. </returns>
		public virtual AlgorithmIdentifier getMacAlgorithm()
		{
			return macAlg;
		}

		/// <summary>
		/// return the object identifier for the content MAC algorithm.
		/// </summary>
		public virtual string getMacAlgOID()
		{
			return macAlg.getAlgorithm().getId();
		}

		/// <summary>
		/// return the ASN.1 encoded MAC algorithm parameters, or null if
		/// there aren't any.
		/// </summary>
		public virtual byte[] getMacAlgParams()
		{
			try
			{
				return encodeObj(macAlg.getParameters());
			}
			catch (Exception e)
			{
				throw new RuntimeException("exception getting encryption parameters " + e);
			}
		}

		/// <summary>
		/// return a store of the intended recipients for this message
		/// </summary>
		public virtual RecipientInformationStore getRecipientInfos()
		{
			return recipientInfoStore;
		}

		/// <summary>
		/// return the ContentInfo </summary>
		/// @deprecated use toASN1Structure() 
		public virtual ContentInfo getContentInfo()
		{
			return contentInfo;
		}

		/// <summary>
		/// return the ContentInfo
		/// </summary>
		public virtual ContentInfo toASN1Structure()
		{
			return contentInfo;
		}

		/// <summary>
		/// return a table of the digested attributes indexed by
		/// the OID of the attribute.
		/// </summary>
		public virtual AttributeTable getAuthAttrs()
		{
			if (authAttrs == null)
			{
				return null;
			}

			return new AttributeTable(authAttrs);
		}

		/// <summary>
		/// return a table of the undigested attributes indexed by
		/// the OID of the attribute.
		/// </summary>
		public virtual AttributeTable getUnauthAttrs()
		{
			if (unauthAttrs == null)
			{
				return null;
			}

			return new AttributeTable(unauthAttrs);
		}

		/// <summary>
		/// return the ASN.1 encoded representation of this object.
		/// </summary>
		public virtual byte[] getEncoded()
		{
			return contentInfo.getEncoded();
		}

		public virtual byte[] getContentDigest()
		{
			if (authAttrs != null)
			{
				return ASN1OctetString.getInstance(getAuthAttrs().get(CMSAttributes_Fields.messageDigest).getAttrValues().getObjectAt(0)).getOctets();
			}

			return null;
		}
	}

}