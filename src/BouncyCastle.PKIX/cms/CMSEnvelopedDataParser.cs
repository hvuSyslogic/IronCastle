using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1OctetStringParser = org.bouncycastle.asn1.ASN1OctetStringParser;
	using ASN1SequenceParser = org.bouncycastle.asn1.ASN1SequenceParser;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using ASN1SetParser = org.bouncycastle.asn1.ASN1SetParser;
	using BERTags = org.bouncycastle.asn1.BERTags;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using EncryptedContentInfoParser = org.bouncycastle.asn1.cms.EncryptedContentInfoParser;
	using EnvelopedDataParser = org.bouncycastle.asn1.cms.EnvelopedDataParser;
	using OriginatorInfo = org.bouncycastle.asn1.cms.OriginatorInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// Parsing class for an CMS Enveloped Data object from an input stream.
	/// <para>
	/// Note: that because we are in a streaming mode only one recipient can be tried and it is important 
	/// that the methods on the parser are called in the appropriate order.
	/// </para>
	/// <para>
	/// Example of use - assuming the first recipient matches the private key we have.
	/// <pre>
	///      CMSEnvelopedDataParser     ep = new CMSEnvelopedDataParser(inputStream);
	/// 
	///      RecipientInformationStore  recipients = ep.getRecipientInfos();
	/// 
	///      Collection  c = recipients.getRecipients();
	///      Iterator    it = c.iterator();
	/// 
	///      if (it.hasNext())
	///      {
	///          RecipientInformation   recipient = (RecipientInformation)it.next();
	/// 
	///          CMSTypedStream recData = recipient.getContentStream(new JceKeyTransEnvelopedRecipient(privateKey).setProvider("BC"));
	/// 
	///          processDataStream(recData.getContentStream());
	///      }
	///  </pre>
	///  Note: this class does not introduce buffering - if you are processing large files you should create
	///  the parser with:
	///  <pre>
	///          CMSEnvelopedDataParser     ep = new CMSEnvelopedDataParser(new BufferedInputStream(inputStream, bufSize));
	///  </pre>
	///  where bufSize is a suitably large buffer size.
	/// </para>
	/// </summary>
	public class CMSEnvelopedDataParser : CMSContentInfoParser
	{
		internal RecipientInformationStore recipientInfoStore;
		internal EnvelopedDataParser envelopedData;

		private AlgorithmIdentifier encAlg;
		private AttributeTable unprotectedAttributes;
		private bool attrNotRead;
		private OriginatorInformation originatorInfo;

		public CMSEnvelopedDataParser(byte[] envelopedData) : this(new ByteArrayInputStream(envelopedData))
		{
		}

		public CMSEnvelopedDataParser(InputStream envelopedData) : base(envelopedData)
		{

			this.attrNotRead = true;
			this.envelopedData = new EnvelopedDataParser((ASN1SequenceParser)_contentInfo.getContent(BERTags_Fields.SEQUENCE));

			// TODO Validate version?
			//ASN1Integer version = this._envelopedData.getVersion();

			OriginatorInfo info = this.envelopedData.getOriginatorInfo();

			if (info != null)
			{
				this.originatorInfo = new OriginatorInformation(info);
			}

			//
			// read the recipients
			//
			ASN1Set recipientInfos = ASN1Set.getInstance(this.envelopedData.getRecipientInfos().toASN1Primitive());

			//
			// read the encrypted content info
			//
			EncryptedContentInfoParser encInfo = this.envelopedData.getEncryptedContentInfo();
			this.encAlg = encInfo.getContentEncryptionAlgorithm();
			CMSReadable readable = new CMSProcessableInputStream(((ASN1OctetStringParser)encInfo.getEncryptedContent(BERTags_Fields.OCTET_STRING)).getOctetStream());
			CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSEnvelopedSecureReadable(this.encAlg, readable);

			//
			// build the RecipientInformationStore
			//
			this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, this.encAlg, secureReadable);
		}

		/// <summary>
		/// return the object identifier for the content encryption algorithm.
		/// </summary>
		public virtual string getEncryptionAlgOID()
		{
			return encAlg.getAlgorithm().ToString();
		}

		/// <summary>
		/// return the ASN.1 encoded encryption algorithm parameters, or null if
		/// there aren't any.
		/// </summary>
		public virtual byte[] getEncryptionAlgParams()
		{
			try
			{
				return encodeObj(encAlg.getParameters());
			}
			catch (Exception e)
			{
				throw new RuntimeException("exception getting encryption parameters " + e);
			}
		}

		/// <summary>
		/// Return the content encryption algorithm details for the data in this object.
		/// </summary>
		/// <returns> AlgorithmIdentifier representing the content encryption algorithm. </returns>
		public virtual AlgorithmIdentifier getContentEncryptionAlgorithm()
		{
			return encAlg;
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
		/// return a store of the intended recipients for this message
		/// </summary>
		public virtual RecipientInformationStore getRecipientInfos()
		{
			return recipientInfoStore;
		}

		/// <summary>
		/// return a table of the unprotected attributes indexed by
		/// the OID of the attribute. </summary>
		/// <exception cref="IOException">  </exception>
		public virtual AttributeTable getUnprotectedAttributes()
		{
			if (unprotectedAttributes == null && attrNotRead)
			{
				ASN1SetParser set = envelopedData.getUnprotectedAttrs();

				attrNotRead = false;

				if (set != null)
				{
					ASN1EncodableVector v = new ASN1EncodableVector();
					ASN1Encodable o;

					while ((o = set.readObject()) != null)
					{
						ASN1SequenceParser seq = (ASN1SequenceParser)o;

						v.add(seq.toASN1Primitive());
					}

					unprotectedAttributes = new AttributeTable(new DERSet(v));
				}
			}

			return unprotectedAttributes;
		}

		private byte[] encodeObj(ASN1Encodable obj)
		{
			if (obj != null)
			{
				return obj.toASN1Primitive().getEncoded();
			}

			return null;
		}
	}

}