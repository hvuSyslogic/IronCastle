using org.bouncycastle.asn1;

namespace org.bouncycastle.cms.jcajce
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using OperatorException = org.bouncycastle.@operator.OperatorException;
	using JceKTSKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceKTSKeyUnwrapper;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public abstract class JceKTSKeyTransRecipient : KeyTransRecipient
	{
		public abstract RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey);
		private bool InstanceFieldsInitialized = false;

		private void InitializeInstanceFields()
		{
			contentHelper = helper;
		}

		private static readonly byte[] ANONYMOUS_SENDER = Hex.decode("0c14416e6f6e796d6f75732053656e64657220202020"); // "Anonymous Sender    "
		private readonly byte[] partyVInfo;

		private PrivateKey recipientKey;

		protected internal EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
		protected internal EnvelopedDataHelper contentHelper;
		protected internal Map extraMappings = new HashMap();
		protected internal bool validateKeySize = false;
		protected internal bool unwrappedKeyMustBeEncodable;

		public JceKTSKeyTransRecipient(PrivateKey recipientKey, byte[] partyVInfo)
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
			this.recipientKey = recipientKey;
			this.partyVInfo = partyVInfo;
		}

		/// <summary>
		/// Set the provider to use for key recovery and content processing.
		/// </summary>
		/// <param name="provider"> provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKTSKeyTransRecipient setProvider(Provider provider)
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
		public virtual JceKTSKeyTransRecipient setProvider(string providerName)
		{
			this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
			this.contentHelper = helper;

			return this;
		}

		/// <summary>
		/// Internally algorithm ids are converted into cipher names using a lookup table. For some providers
		/// the standard lookup table won't work. Use this method to establish a specific mapping from an
		/// algorithm identifier to a specific algorithm.
		/// <para>
		///     For example:
		/// <pre>
		///     unwrapper.setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA");
		/// </pre>
		/// </para>
		/// </summary>
		/// <param name="algorithm">  OID of algorithm in recipient. </param>
		/// <param name="algorithmName"> JCE algorithm name to use. </param>
		/// <returns> the current Recipient. </returns>
		public virtual JceKTSKeyTransRecipient setAlgorithmMapping(ASN1ObjectIdentifier algorithm, string algorithmName)
		{
			extraMappings.put(algorithm, algorithmName);

			return this;
		}

		/// <summary>
		/// Set the provider to use for content processing.  If providerName is null a "no provider" search will be
		/// used to satisfy getInstance calls.
		/// </summary>
		/// <param name="provider"> the provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKTSKeyTransRecipient setContentProvider(Provider provider)
		{
			this.contentHelper = CMSUtils.createContentHelper(provider);

			return this;
		}

		/// <summary>
		/// Set the provider to use for content processing.  If providerName is null a "no provider" search will be
		///  used to satisfy getInstance calls.
		/// </summary>
		/// <param name="providerName"> the name of the provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKTSKeyTransRecipient setContentProvider(string providerName)
		{
			this.contentHelper = CMSUtils.createContentHelper(providerName);

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
		public virtual JceKTSKeyTransRecipient setKeySizeValidation(bool doValidate)
		{
			this.validateKeySize = doValidate;

			return this;
		}

		public virtual Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedEncryptionKey)
		{
			JceKTSKeyUnwrapper unwrapper = helper.createAsymmetricUnwrapper(keyEncryptionAlgorithm, recipientKey, ANONYMOUS_SENDER, partyVInfo);

			try
			{
				Key key = helper.getJceKey(encryptedKeyAlgorithm.getAlgorithm(), unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));

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

		protected internal static byte[] getPartyVInfoFromRID(KeyTransRecipientId recipientId)
		{
			if (recipientId.getSerialNumber() != null)
			{
				return (new IssuerAndSerialNumber(recipientId.getIssuer(), recipientId.getSerialNumber())).getEncoded(ASN1Encoding_Fields.DER);
			}
			else
			{
				return (new DEROctetString(recipientId.getSubjectKeyIdentifier())).getEncoded();
			}
		}
	}

}