using org.bouncycastle.cms;

using System;

namespace org.bouncycastle.cms.bc
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using PBEParametersGenerator = org.bouncycastle.crypto.PBEParametersGenerator;
	using Wrapper = org.bouncycastle.crypto.Wrapper;
	using PKCS5S2ParametersGenerator = org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using GenericKey = org.bouncycastle.@operator.GenericKey;

	public class BcPasswordRecipientInfoGenerator : PasswordRecipientInfoGenerator
	{
		public BcPasswordRecipientInfoGenerator(ASN1ObjectIdentifier kekAlgorithm, char[] password) : base(kekAlgorithm, password)
		{
		}

		public override byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize)
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

		public override byte[] generateEncryptedBytes(AlgorithmIdentifier keyEncryptionAlgorithm, byte[] derivedKey, GenericKey contentEncryptionKey)
		{
			byte[] contentEncryptionKeySpec = ((KeyParameter)CMSUtils.getBcKey(contentEncryptionKey)).getKey();
			Wrapper keyEncryptionCipher = EnvelopedDataHelper.createRFC3211Wrapper(keyEncryptionAlgorithm.getAlgorithm());

			keyEncryptionCipher.init(true, new ParametersWithIV(new KeyParameter(derivedKey), ASN1OctetString.getInstance(keyEncryptionAlgorithm.getParameters()).getOctets()));

			return keyEncryptionCipher.wrap(contentEncryptionKeySpec, 0, contentEncryptionKeySpec.Length);
		}
	}

}