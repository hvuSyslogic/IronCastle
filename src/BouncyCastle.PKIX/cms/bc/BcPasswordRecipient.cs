using org.bouncycastle.cms;

using System;

namespace org.bouncycastle.cms.bc
{
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using PBEParametersGenerator = org.bouncycastle.crypto.PBEParametersGenerator;
	using Wrapper = org.bouncycastle.crypto.Wrapper;
	using PKCS5S2ParametersGenerator = org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

	/// <summary>
	/// the RecipientInfo class for a recipient who has been sent a message
	/// encrypted using a password.
	/// </summary>
	public abstract class BcPasswordRecipient : PasswordRecipient
	{
		public abstract RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey, byte[] encryptedEncryptedContentKey);
		private readonly char[] password;

		private int schemeID = PasswordRecipient_Fields.PKCS5_SCHEME2_UTF8;

		public BcPasswordRecipient(char[] password)
		{
			this.password = password;
		}

		public virtual BcPasswordRecipient setPasswordConversionScheme(int schemeID)
		{
			this.schemeID = schemeID;

			return this;
		}

		public virtual KeyParameter extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey, byte[] encryptedContentEncryptionKey)
		{
			Wrapper keyEncryptionCipher = EnvelopedDataHelper.createRFC3211Wrapper(keyEncryptionAlgorithm.getAlgorithm());

			keyEncryptionCipher.init(false, new ParametersWithIV(new KeyParameter(derivedKey), ASN1OctetString.getInstance(keyEncryptionAlgorithm.getParameters()).getOctets()));

			try
			{
				return new KeyParameter(keyEncryptionCipher.unwrap(encryptedContentEncryptionKey, 0, encryptedContentEncryptionKey.Length));
			}
			catch (InvalidCipherTextException e)
			{
				throw new CMSException("unable to unwrap key: " + e.Message, e);
			}
		}

		public virtual byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize)
		{
			PBKDF2Params @params = PBKDF2Params.getInstance(derivationAlgorithm.getParameters());
			byte[] encodedPassword = (schemeID == PasswordRecipient_Fields.PKCS5_SCHEME2) ? PBEParametersGenerator.PKCS5PasswordToBytes(password) : PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);

			try
			{
				PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(EnvelopedDataHelper.getPRF(@params.getPrf()));

				gen.init(encodedPassword, @params.getSalt(), @params.getIterationCount().intValue());

				return ((KeyParameter)gen.generateDerivedParameters(keySize)).getKey();
			}
			catch (Exception e)
			{
				throw new CMSException("exception creating derived key: " + e.Message, e);
			}
		}

		public virtual int getPasswordConversionScheme()
		{
			return schemeID;
		}

		public virtual char[] getPassword()
		{
			return password;
		}
	}

}