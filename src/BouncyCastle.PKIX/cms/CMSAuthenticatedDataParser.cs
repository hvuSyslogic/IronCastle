using org.bouncycastle.asn1;
using org.bouncycastle.asn1.cms;

using System;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1OctetStringParser = org.bouncycastle.asn1.ASN1OctetStringParser;
	using ASN1SequenceParser = org.bouncycastle.asn1.ASN1SequenceParser;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using ASN1SetParser = org.bouncycastle.asn1.ASN1SetParser;
	using BERTags = org.bouncycastle.asn1.BERTags;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using AuthenticatedDataParser = org.bouncycastle.asn1.cms.AuthenticatedDataParser;
	using CMSAttributes = org.bouncycastle.asn1.cms.CMSAttributes;
	using ContentInfoParser = org.bouncycastle.asn1.cms.ContentInfoParser;
	using OriginatorInfo = org.bouncycastle.asn1.cms.OriginatorInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Parsing class for an CMS Authenticated Data object from an input stream.
	/// <para>
	/// Note: that because we are in a streaming mode only one recipient can be tried and it is important
	/// that the methods on the parser are called in the appropriate order.
	/// </para>
	/// <para>
	/// Example of use - assuming the first recipient matches the private key we have.
	/// <pre>
	///      CMSAuthenticatedDataParser     ad = new CMSAuthenticatedDataParser(inputStream);
	/// 
	///      RecipientInformationStore  recipients = ad.getRecipientInfos();
	/// 
	///      Collection  c = recipients.getRecipients();
	///      Iterator    it = c.iterator();
	/// 
	///      if (it.hasNext())
	///      {
	///          RecipientInformation   recipient = (RecipientInformation)it.next();
	/// 
	///          CMSTypedStream recData = recipient.getContentStream(new JceKeyTransAuthenticatedRecipient(privateKey).setProvider("BC"));
	/// 
	///          processDataStream(recData.getContentStream());
	/// 
	///          if (!Arrays.equals(ad.getMac(), recipient.getMac())
	///          {
	///              JavaSystem.err.println("Data corrupted!!!!");
	///          }
	///      }
	///  </pre>
	///  Note: this class does not introduce buffering - if you are processing large files you should create
	///  the parser with:
	///  <pre>
	///          CMSAuthenticatedDataParser     ep = new CMSAuthenticatedDataParser(new BufferedInputStream(inputStream, bufSize));
	///  </pre>
	///  where bufSize is a suitably large buffer size.
	/// </para>
	/// </summary>
	public class CMSAuthenticatedDataParser : CMSContentInfoParser
	{
		internal RecipientInformationStore recipientInfoStore;
		internal AuthenticatedDataParser authData;

		private AlgorithmIdentifier macAlg;
		private byte[] mac;
		private AttributeTable authAttrs;
		private ASN1Set authAttrSet;
		private AttributeTable unauthAttrs;

		private bool authAttrNotRead;
		private bool unauthAttrNotRead;
		private OriginatorInformation originatorInfo;

		public CMSAuthenticatedDataParser(byte[] envelopedData) : this(new ByteArrayInputStream(envelopedData))
		{
		}

		public CMSAuthenticatedDataParser(byte[] envelopedData, DigestCalculatorProvider digestCalculatorProvider) : this(new ByteArrayInputStream(envelopedData), digestCalculatorProvider)
		{
		}

		public CMSAuthenticatedDataParser(InputStream envelopedData) : this(envelopedData, null)
		{
		}

		public CMSAuthenticatedDataParser(InputStream envelopedData, DigestCalculatorProvider digestCalculatorProvider) : base(envelopedData)
		{

			this.authAttrNotRead = true;
			this.authData = new AuthenticatedDataParser((ASN1SequenceParser)_contentInfo.getContent(BERTags_Fields.SEQUENCE));

			// TODO Validate version?
			//ASN1Integer version = this.authData.getVersion();

			OriginatorInfo info = authData.getOriginatorInfo();

			if (info != null)
			{
				this.originatorInfo = new OriginatorInformation(info);
			}
			//
			// read the recipients
			//
			ASN1Set recipientInfos = ASN1Set.getInstance(authData.getRecipientInfos().toASN1Primitive());

			this.macAlg = authData.getMacAlgorithm();

			//
			// build the RecipientInformationStore
			//
			AlgorithmIdentifier digestAlgorithm = authData.getDigestAlgorithm();

			if (digestAlgorithm != null)
			{
				if (digestCalculatorProvider == null)
				{
					throw new CMSException("a digest calculator provider is required if authenticated attributes are present");
				}

				//
				// read the authenticated content info
				//
				ContentInfoParser data = authData.getEncapsulatedContentInfo();
				CMSReadable readable = new CMSProcessableInputStream(((ASN1OctetStringParser)data.getContent(BERTags_Fields.OCTET_STRING)).getOctetStream());

				try
				{
					CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSDigestAuthenticatedSecureReadable(digestCalculatorProvider.get(digestAlgorithm), readable);

					this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, this.macAlg, secureReadable, new AuthAttributesProviderAnonymousInnerClass(this));
				}
				catch (OperatorCreationException e)
				{
					throw new CMSException("unable to create digest calculator: " + e.Message, e);
				}
			}
			else
			{
				//
				// read the authenticated content info
				//
				ContentInfoParser data = authData.getEncapsulatedContentInfo();
				CMSReadable readable = new CMSProcessableInputStream(((ASN1OctetStringParser)data.getContent(BERTags_Fields.OCTET_STRING)).getOctetStream());

				CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSAuthenticatedSecureReadable(this.macAlg, readable);

				this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, this.macAlg, secureReadable);
			}


		}

		public class AuthAttributesProviderAnonymousInnerClass : AuthAttributesProvider
		{
			private readonly CMSAuthenticatedDataParser outerInstance;

			public AuthAttributesProviderAnonymousInnerClass(CMSAuthenticatedDataParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public ASN1Set getAuthAttributes()
			{
				try
				{
					return outerInstance.getAuthAttrSet();
				}
				catch (IOException)
				{
					throw new IllegalStateException("can't parse authenticated attributes!");
				}
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

		/// <summary>
		/// Return the MAC algorithm details for the MAC associated with the data in this object.
		/// </summary>
		/// <returns> AlgorithmIdentifier representing the MAC algorithm. </returns>
		public virtual AlgorithmIdentifier getMacAlgorithm()
		{
			return macAlg;
		}

		/// <summary>
		/// return the object identifier for the mac algorithm.
		/// </summary>
		public virtual string getMacAlgOID()
		{
			return macAlg.getAlgorithm().ToString();
		}

		/// <summary>
		/// return the ASN.1 encoded encryption algorithm parameters, or null if
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

		public virtual byte[] getMac()
		{
			if (mac == null)
			{
				getAuthAttrs();
				mac = authData.getMac().getOctets();
			}
			return Arrays.clone(mac);
		}

		private ASN1Set getAuthAttrSet()
		{
			if (authAttrs == null && authAttrNotRead)
			{
				ASN1SetParser set = authData.getAuthAttrs();

				if (set != null)
				{
					authAttrSet = (ASN1Set)set.toASN1Primitive();
				}

				authAttrNotRead = false;
			}

			return authAttrSet;
		}

		/// <summary>
		/// return a table of the unauthenticated attributes indexed by
		/// the OID of the attribute. </summary>
		/// <exception cref="java.io.IOException"> </exception>
		public virtual AttributeTable getAuthAttrs()
		{
			if (authAttrs == null && authAttrNotRead)
			{
				ASN1Set set = getAuthAttrSet();

				if (set != null)
				{
					authAttrs = new AttributeTable(set);
				}
			}

			return authAttrs;
		}

		/// <summary>
		/// return a table of the unauthenticated attributes indexed by
		/// the OID of the attribute. </summary>
		/// <exception cref="java.io.IOException"> </exception>
		public virtual AttributeTable getUnauthAttrs()
		{
			if (unauthAttrs == null && unauthAttrNotRead)
			{
				ASN1SetParser set = authData.getUnauthAttrs();

				unauthAttrNotRead = false;

				if (set != null)
				{
					ASN1EncodableVector v = new ASN1EncodableVector();
					ASN1Encodable o;

					while ((o = set.readObject()) != null)
					{
						ASN1SequenceParser seq = (ASN1SequenceParser)o;

						v.add(seq.toASN1Primitive());
					}

					unauthAttrs = new AttributeTable(new DERSet(v));
				}
			}

			return unauthAttrs;
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
		/// This will only be valid after the content has been read.
		/// </summary>
		/// <returns> the contents of the messageDigest attribute, if available. Null if not present. </returns>
		public virtual byte[] getContentDigest()
		{
			if (authAttrs != null)
			{
				return ASN1OctetString.getInstance(authAttrs.get(CMSAttributes_Fields.messageDigest).getAttrValues().getObjectAt(0)).getOctets();
			}

			return null;
		}
	}

}