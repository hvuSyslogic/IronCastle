using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using BEROctetString = org.bouncycastle.asn1.BEROctetString;
	using BERSet = org.bouncycastle.asn1.BERSet;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using EncryptedContentInfo = org.bouncycastle.asn1.cms.EncryptedContentInfo;
	using EncryptedData = org.bouncycastle.asn1.cms.EncryptedData;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;

	/// <summary>
	/// General class for generating a CMS encrypted-data message.
	/// 
	/// A simple example of usage.
	/// 
	/// <pre>
	///       CMSTypedData msg     = new CMSProcessableByteArray("Hello World!".getBytes());
	/// 
	///       CMSEncryptedDataGenerator edGen = new CMSEncryptedDataGenerator();
	/// 
	///       CMSEncryptedData ed = edGen.generate(
	///                                       msg,
	///                                       new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
	///                                              .setProvider("BC").build());
	/// 
	/// </pre>
	/// </summary>
	public class CMSEncryptedDataGenerator : CMSEncryptedGenerator
	{
		/// <summary>
		/// base constructor
		/// </summary>
		public CMSEncryptedDataGenerator()
		{
		}

		private CMSEncryptedData doGenerate(CMSTypedData content, OutputEncryptor contentEncryptor)
		{
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

			EncryptedContentInfo eci = new EncryptedContentInfo(content.getContentType(), encAlgId, encContent);

			ASN1Set unprotectedAttrSet = null;
			if (unprotectedAttributeGenerator != null)
			{
				AttributeTable attrTable = unprotectedAttributeGenerator.getAttributes(new HashMap());

				unprotectedAttrSet = new BERSet(attrTable.toASN1EncodableVector());
			}

			ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers_Fields.encryptedData, new EncryptedData(eci, unprotectedAttrSet));

			return new CMSEncryptedData(contentInfo);
		}

		/// <summary>
		/// generate an encrypted object that contains an CMS Encrypted Data structure.
		/// </summary>
		/// <param name="content"> the content to be encrypted </param>
		/// <param name="contentEncryptor"> the symmetric key based encryptor to encrypt the content with. </param>
		public virtual CMSEncryptedData generate(CMSTypedData content, OutputEncryptor contentEncryptor)
		{
			return doGenerate(content, contentEncryptor);
		}
	}

}