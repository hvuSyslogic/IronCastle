using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using BEROctetString = org.bouncycastle.asn1.BEROctetString;
	using BERSet = org.bouncycastle.asn1.BERSet;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using EncryptedContentInfo = org.bouncycastle.asn1.cms.EncryptedContentInfo;
	using EnvelopedData = org.bouncycastle.asn1.cms.EnvelopedData;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;

	/// <summary>
	/// General class for generating a CMS enveloped-data message.
	/// 
	/// A simple example of usage.
	/// 
	/// <pre>
	///       CMSTypedData msg     = new CMSProcessableByteArray("Hello World!".getBytes());
	/// 
	///       CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
	/// 
	///       edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));
	/// 
	///       CMSEnvelopedData ed = edGen.generate(
	///                                       msg,
	///                                       new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
	///                                              .setProvider("BC").build());
	/// 
	/// </pre>
	/// </summary>
	public class CMSEnvelopedDataGenerator : CMSEnvelopedGenerator
	{
		/// <summary>
		/// base constructor
		/// </summary>
		public CMSEnvelopedDataGenerator()
		{
		}

		private CMSEnvelopedData doGenerate(CMSTypedData content, OutputEncryptor contentEncryptor)
		{
			if (!oldRecipientInfoGenerators.isEmpty())
			{
				throw new IllegalStateException("can only use addRecipientGenerator() with this method");
			}

			ASN1EncodableVector recipientInfos = new ASN1EncodableVector();
			AlgorithmIdentifier encAlgId;
			ASN1OctetString encContent;

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try
			{
				OutputStream cOut = contentEncryptor.getOutputStream(bOut);

				content.write(cOut);

				cOut.close();
			}
			catch (IOException)
			{
				throw new CMSException("");
			}

			byte[] encryptedContent = bOut.toByteArray();

			encAlgId = contentEncryptor.getAlgorithmIdentifier();

			encContent = new BEROctetString(encryptedContent);

			GenericKey encKey = contentEncryptor.getKey();

			for (Iterator it = recipientInfoGenerators.iterator(); it.hasNext();)
			{
				RecipientInfoGenerator recipient = (RecipientInfoGenerator)it.next();

				recipientInfos.add(recipient.generate(encKey));
			}

			EncryptedContentInfo eci = new EncryptedContentInfo(content.getContentType(), encAlgId, encContent);

			ASN1Set unprotectedAttrSet = null;
			if (unprotectedAttributeGenerator != null)
			{
				AttributeTable attrTable = unprotectedAttributeGenerator.getAttributes(new HashMap());

				unprotectedAttrSet = new BERSet(attrTable.toASN1EncodableVector());
			}

			ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers_Fields.envelopedData, new EnvelopedData(originatorInfo, new DERSet(recipientInfos), eci, unprotectedAttrSet));

			return new CMSEnvelopedData(contentInfo);
		}

		/// <summary>
		/// generate an enveloped object that contains an CMS Enveloped Data
		/// object using the given provider.
		/// </summary>
		/// <param name="content"> the content to be encrypted </param>
		/// <param name="contentEncryptor"> the symmetric key based encryptor to encrypt the content with. </param>
		public virtual CMSEnvelopedData generate(CMSTypedData content, OutputEncryptor contentEncryptor)
		{
			return doGenerate(content, contentEncryptor);
		}
	}

}