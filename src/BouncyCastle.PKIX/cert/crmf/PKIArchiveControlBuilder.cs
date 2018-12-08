using org.bouncycastle.asn1.crmf;

namespace org.bouncycastle.cert.crmf
{

	using EnvelopedData = org.bouncycastle.asn1.cms.EnvelopedData;
	using CRMFObjectIdentifiers = org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
	using EncKeyWithID = org.bouncycastle.asn1.crmf.EncKeyWithID;
	using EncryptedKey = org.bouncycastle.asn1.crmf.EncryptedKey;
	using PKIArchiveOptions = org.bouncycastle.asn1.crmf.PKIArchiveOptions;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using CMSEnvelopedData = org.bouncycastle.cms.CMSEnvelopedData;
	using CMSEnvelopedDataGenerator = org.bouncycastle.cms.CMSEnvelopedDataGenerator;
	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSProcessableByteArray = org.bouncycastle.cms.CMSProcessableByteArray;
	using RecipientInfoGenerator = org.bouncycastle.cms.RecipientInfoGenerator;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;

	/// <summary>
	/// Builder for a PKIArchiveControl structure.
	/// </summary>
	public class PKIArchiveControlBuilder
	{
		private CMSEnvelopedDataGenerator envGen;
		private CMSProcessableByteArray keyContent;

		/// <summary>
		/// Basic constructor - specify the contents of the PKIArchiveControl structure.
		/// </summary>
		/// <param name="privateKeyInfo"> the private key to be archived. </param>
		/// <param name="generalName"> the general name to be associated with the private key. </param>
		public PKIArchiveControlBuilder(PrivateKeyInfo privateKeyInfo, GeneralName generalName)
		{
			EncKeyWithID encKeyWithID = new EncKeyWithID(privateKeyInfo, generalName);

			try
			{
				this.keyContent = new CMSProcessableByteArray(CRMFObjectIdentifiers_Fields.id_ct_encKeyWithID, encKeyWithID.getEncoded());
			}
			catch (IOException)
			{
				throw new IllegalStateException("unable to encode key and general name info");
			}

			this.envGen = new CMSEnvelopedDataGenerator();
		}

		/// <summary>
		/// Add a recipient generator to this control.
		/// </summary>
		/// <param name="recipientGen"> recipient generator created for a specific recipient. </param>
		/// <returns> this builder object. </returns>
		public virtual PKIArchiveControlBuilder addRecipientGenerator(RecipientInfoGenerator recipientGen)
		{
			envGen.addRecipientInfoGenerator(recipientGen);

			return this;
		}

		/// <summary>
		/// Build the PKIArchiveControl using the passed in encryptor to encrypt its contents.
		/// </summary>
		/// <param name="contentEncryptor"> a suitable content encryptor. </param>
		/// <returns> a PKIArchiveControl object. </returns>
		/// <exception cref="CMSException"> in the event the build fails. </exception>
		public virtual PKIArchiveControl build(OutputEncryptor contentEncryptor)
		{
			CMSEnvelopedData envContent = envGen.generate(keyContent, contentEncryptor);

			EnvelopedData envD = EnvelopedData.getInstance(envContent.toASN1Structure().getContent());

			return new PKIArchiveControl(new PKIArchiveOptions(new EncryptedKey(envD)));
		}
	}
}