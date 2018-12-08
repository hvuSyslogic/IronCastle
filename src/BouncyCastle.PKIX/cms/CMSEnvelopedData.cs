using System;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using EncryptedContentInfo = org.bouncycastle.asn1.cms.EncryptedContentInfo;
	using EnvelopedData = org.bouncycastle.asn1.cms.EnvelopedData;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// containing class for an CMS Enveloped Data object
	/// <para>
	/// Example of use - assuming the first recipient matches the private key we have.
	/// <pre>
	///      CMSEnvelopedData     ed = new CMSEnvelopedData(inputStream);
	/// 
	///      RecipientInformationStore  recipients = ed.getRecipientInfos();
	/// 
	///      Collection  c = recipients.getRecipients();
	///      Iterator    it = c.iterator();
	/// 
	///      if (it.hasNext())
	///      {
	///          RecipientInformation   recipient = (RecipientInformation)it.next();
	/// 
	///          byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey).setProvider("BC"));
	/// 
	///          processData(recData);
	///      }
	///  </pre>
	/// </para>
	/// </summary>
	public class CMSEnvelopedData : Encodable
	{
		internal RecipientInformationStore recipientInfoStore;
		internal ContentInfo contentInfo;

		private AlgorithmIdentifier encAlg;
		private ASN1Set unprotectedAttributes;
		private OriginatorInformation originatorInfo;

		public CMSEnvelopedData(byte[] envelopedData) : this(CMSUtils.readContentInfo(envelopedData))
		{
		}

		public CMSEnvelopedData(InputStream envelopedData) : this(CMSUtils.readContentInfo(envelopedData))
		{
		}

		/// <summary>
		/// Construct a CMSEnvelopedData object from a content info object.
		/// </summary>
		/// <param name="contentInfo"> the contentInfo containing the CMS EnvelopedData object. </param>
		/// <exception cref="CMSException"> in the case where malformed content is encountered. </exception>
		public CMSEnvelopedData(ContentInfo contentInfo)
		{
			this.contentInfo = contentInfo;

			try
			{
				EnvelopedData envData = EnvelopedData.getInstance(contentInfo.getContent());

				if (envData.getOriginatorInfo() != null)
				{
					originatorInfo = new OriginatorInformation(envData.getOriginatorInfo());
				}

				//
				// read the recipients
				//
				ASN1Set recipientInfos = envData.getRecipientInfos();

				//
				// read the encrypted content info
				//
				EncryptedContentInfo encInfo = envData.getEncryptedContentInfo();
				this.encAlg = encInfo.getContentEncryptionAlgorithm();
				CMSReadable readable = new CMSProcessableByteArray(encInfo.getEncryptedContent().getOctets());
				CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSEnvelopedSecureReadable(this.encAlg, readable);

				//
				// build the RecipientInformationStore
				//
				this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, this.encAlg, secureReadable);

				this.unprotectedAttributes = envData.getUnprotectedAttrs();
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

		private byte[] encodeObj(ASN1Encodable obj)
		{
			if (obj != null)
			{
				return obj.toASN1Primitive().getEncoded();
			}

			return null;
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
		/// Return the content encryption algorithm details for the data in this object.
		/// </summary>
		/// <returns> AlgorithmIdentifier representing the content encryption algorithm. </returns>
		public virtual AlgorithmIdentifier getContentEncryptionAlgorithm()
		{
			return encAlg;
		}

		/// <summary>
		/// return the object identifier for the content encryption algorithm.
		/// </summary>
		public virtual string getEncryptionAlgOID()
		{
			return encAlg.getAlgorithm().getId();
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
		/// return a store of the intended recipients for this message
		/// </summary>
		public virtual RecipientInformationStore getRecipientInfos()
		{
			return recipientInfoStore;
		}

		/// <summary>
		/// return the ContentInfo
		/// </summary>
		public virtual ContentInfo toASN1Structure()
		{
			return contentInfo;
		}

		/// <summary>
		/// return a table of the unprotected attributes indexed by
		/// the OID of the attribute.
		/// </summary>
		public virtual AttributeTable getUnprotectedAttributes()
		{
			if (unprotectedAttributes == null)
			{
				return null;
			}

			return new AttributeTable(unprotectedAttributes);
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