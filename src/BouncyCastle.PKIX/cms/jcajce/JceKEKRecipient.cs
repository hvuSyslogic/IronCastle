namespace org.bouncycastle.cms.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using OperatorException = org.bouncycastle.@operator.OperatorException;
	using SymmetricKeyUnwrapper = org.bouncycastle.@operator.SymmetricKeyUnwrapper;

	public abstract class JceKEKRecipient : KEKRecipient
	{
		public abstract RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey);
		private bool InstanceFieldsInitialized = false;

		private void InitializeInstanceFields()
		{
			contentHelper = helper;
		}

		private SecretKey recipientKey;

		protected internal EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
		protected internal EnvelopedDataHelper contentHelper;
		protected internal bool validateKeySize = false;

		public JceKEKRecipient(SecretKey recipientKey)
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
			this.recipientKey = recipientKey;
		}

		/// <summary>
		/// Set the provider to use for key recovery and content processing.
		/// </summary>
		/// <param name="provider"> provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKEKRecipient setProvider(Provider provider)
		{
			this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
			this.contentHelper = helper;

			return this;
		}

		/// <summary>
		/// Set the provider to use for key recovery and content processing.
		/// </summary>
		/// <param name="providerName"> the name of the provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKEKRecipient setProvider(string providerName)
		{
			this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
			this.contentHelper = helper;

			return this;
		}

		/// <summary>
		/// Set the provider to use for content processing.
		/// </summary>
		/// <param name="provider"> the provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKEKRecipient setContentProvider(Provider provider)
		{
			this.contentHelper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

			return this;
		}

		/// <summary>
		/// Set the provider to use for content processing.
		/// </summary>
		/// <param name="providerName"> the name of the provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKEKRecipient setContentProvider(string providerName)
		{
			this.contentHelper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

			return this;
		}

		/// <summary>
		/// Set validation of retrieved key sizes against the algorithm parameters for the encrypted key where possible - default is off.
		/// <para>
		/// This setting will not have any affect if the encryption algorithm in the recipient does not specify a particular key size, or
		/// if the unwrapper is a HSM and the byte encoding of the unwrapped secret key is not available.
		/// </para> </summary>
		/// <param name="doValidate"> true if unwrapped key's should be validated against the content encryption algorithm, false otherwise. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKEKRecipient setKeySizeValidation(bool doValidate)
		{
			this.validateKeySize = doValidate;

			return this;
		}

		public virtual Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedContentEncryptionKey)
		{
			SymmetricKeyUnwrapper unwrapper = helper.createSymmetricUnwrapper(keyEncryptionAlgorithm, recipientKey);

			try
			{
				Key key = helper.getJceKey(encryptedKeyAlgorithm.getAlgorithm(), unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedContentEncryptionKey));

				if (validateKeySize)
				{
					helper.keySizeCheck(encryptedKeyAlgorithm, key);
				}

				return key;
			}
			catch (OperatorException e)
			{
				throw new CMSException("exception unwrapping key: " + e.Message, e);
			}
		}
	}

}