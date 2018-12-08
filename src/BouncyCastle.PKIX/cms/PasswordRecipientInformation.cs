using System;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using PasswordRecipientInfo = org.bouncycastle.asn1.cms.PasswordRecipientInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Integers = org.bouncycastle.util.Integers;

	/// <summary>
	/// the RecipientInfo class for a recipient who has been sent a message
	/// encrypted using a password.
	/// </summary>
	public class PasswordRecipientInformation : RecipientInformation
	{
		internal static Map KEYSIZES = new HashMap();
		internal static Map BLOCKSIZES = new HashMap();

		static PasswordRecipientInformation()
		{
			BLOCKSIZES.put(CMSAlgorithm.DES_EDE3_CBC, Integers.valueOf(8));
			BLOCKSIZES.put(CMSAlgorithm.AES128_CBC, Integers.valueOf(16));
			BLOCKSIZES.put(CMSAlgorithm.AES192_CBC, Integers.valueOf(16));
			BLOCKSIZES.put(CMSAlgorithm.AES256_CBC, Integers.valueOf(16));

			KEYSIZES.put(CMSAlgorithm.DES_EDE3_CBC, Integers.valueOf(192));
			KEYSIZES.put(CMSAlgorithm.AES128_CBC, Integers.valueOf(128));
			KEYSIZES.put(CMSAlgorithm.AES192_CBC, Integers.valueOf(192));
			KEYSIZES.put(CMSAlgorithm.AES256_CBC, Integers.valueOf(256));
		}

		private PasswordRecipientInfo info;

		public PasswordRecipientInformation(PasswordRecipientInfo info, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable, AuthAttributesProvider additionalData) : base(info.getKeyEncryptionAlgorithm(), messageAlgorithm, secureReadable, additionalData)
		{

			this.info = info;
			this.rid = new PasswordRecipientId();
		}

		/// <summary>
		/// return the object identifier for the key derivation algorithm, or null
		/// if there is none present.
		/// </summary>
		/// <returns> OID for key derivation algorithm, if present. </returns>
		public virtual string getKeyDerivationAlgOID()
		{
			if (info.getKeyDerivationAlgorithm() != null)
			{
				return info.getKeyDerivationAlgorithm().getAlgorithm().getId();
			}

			return null;
		}

		/// <summary>
		/// return the ASN.1 encoded key derivation algorithm parameters, or null if
		/// there aren't any. </summary>
		/// <returns> ASN.1 encoding of key derivation algorithm parameters. </returns>
		public virtual byte[] getKeyDerivationAlgParams()
		{
			try
			{
				if (info.getKeyDerivationAlgorithm() != null)
				{
					ASN1Encodable @params = info.getKeyDerivationAlgorithm().getParameters();
					if (@params != null)
					{
						return @params.toASN1Primitive().getEncoded();
					}
				}

				return null;
			}
			catch (Exception e)
			{
				throw new RuntimeException("exception getting encryption parameters " + e);
			}
		}

		/// <summary>
		/// Return the key derivation algorithm details for the key in this recipient.
		/// </summary>
		/// <returns> AlgorithmIdentifier representing the key derivation algorithm. </returns>
		public virtual AlgorithmIdentifier getKeyDerivationAlgorithm()
		{
			return info.getKeyDerivationAlgorithm();
		}

		public override RecipientOperator getRecipientOperator(Recipient recipient)
		{
			PasswordRecipient pbeRecipient = (PasswordRecipient)recipient;
			AlgorithmIdentifier kekAlg = AlgorithmIdentifier.getInstance(info.getKeyEncryptionAlgorithm());
			AlgorithmIdentifier kekAlgParams = AlgorithmIdentifier.getInstance(kekAlg.getParameters());

			int keySize = ((int?)KEYSIZES.get(kekAlgParams.getAlgorithm())).Value;

			byte[] derivedKey = pbeRecipient.calculateDerivedKey(pbeRecipient.getPasswordConversionScheme(), this.getKeyDerivationAlgorithm(), keySize);

			return pbeRecipient.getRecipientOperator(kekAlgParams, messageAlgorithm, derivedKey, info.getEncryptedKey().getOctets());
		}
	}

}