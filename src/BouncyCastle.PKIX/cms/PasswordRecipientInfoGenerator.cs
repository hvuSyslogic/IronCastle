using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.cms
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using PasswordRecipientInfo = org.bouncycastle.asn1.cms.PasswordRecipientInfo;
	using RecipientInfo = org.bouncycastle.asn1.cms.RecipientInfo;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public abstract class PasswordRecipientInfoGenerator : RecipientInfoGenerator
	{
		protected internal char[] password;

		private AlgorithmIdentifier keyDerivationAlgorithm;
		private ASN1ObjectIdentifier kekAlgorithm;
		private SecureRandom random;
		private int schemeID;
		private int keySize;
		private int blockSize;
		private PasswordRecipient_PRF prf;
		private byte[] salt;
		private int iterationCount;

		public PasswordRecipientInfoGenerator(ASN1ObjectIdentifier kekAlgorithm, char[] password) : this(kekAlgorithm, password, getKeySize(kekAlgorithm), ((int?)PasswordRecipientInformation.BLOCKSIZES.get(kekAlgorithm)).Value)
		{
		}

		public PasswordRecipientInfoGenerator(ASN1ObjectIdentifier kekAlgorithm, char[] password, int keySize, int blockSize)
		{
			this.password = password;
			this.schemeID = PasswordRecipient_Fields.PKCS5_SCHEME2_UTF8;
			this.kekAlgorithm = kekAlgorithm;
			this.keySize = keySize;
			this.blockSize = blockSize;
			this.prf = PasswordRecipient_PRF.HMacSHA1;
			this.iterationCount = 1024;
		}

		private static int getKeySize(ASN1ObjectIdentifier kekAlgorithm)
		{
			int? size = (int?)PasswordRecipientInformation.KEYSIZES.get(kekAlgorithm);

			if (size == null)
			{
				throw new IllegalArgumentException("cannot find key size for algorithm: " + kekAlgorithm);
			}

			return size.Value;
		}

		public virtual PasswordRecipientInfoGenerator setPasswordConversionScheme(int schemeID)
		{
			this.schemeID = schemeID;

			return this;
		}

		public virtual PasswordRecipientInfoGenerator setPRF(PasswordRecipient_PRF prf)
		{
			this.prf = prf;

			return this;
		}

		public virtual PasswordRecipientInfoGenerator setSaltAndIterationCount(byte[] salt, int iterationCount)
		{
			this.salt = Arrays.clone(salt);
			this.iterationCount = iterationCount;

			return this;
		}

		public virtual PasswordRecipientInfoGenerator setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public virtual RecipientInfo generate(GenericKey contentEncryptionKey)
		{
			byte[] iv = new byte[blockSize]; /// TODO: set IV size properly!

			if (random == null)
			{
				random = new SecureRandom();
			}

			random.nextBytes(iv);

			if (salt == null)
			{
				salt = new byte[20];

				random.nextBytes(salt);
			}

			keyDerivationAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_PBKDF2, new PBKDF2Params(salt, iterationCount, prf.prfAlgID));

			byte[] derivedKey = calculateDerivedKey(schemeID, keyDerivationAlgorithm, keySize);

			AlgorithmIdentifier kekAlgorithmId = new AlgorithmIdentifier(kekAlgorithm, new DEROctetString(iv));

			byte[] encryptedKeyBytes = generateEncryptedBytes(kekAlgorithmId, derivedKey, contentEncryptionKey);

			ASN1OctetString encryptedKey = new DEROctetString(encryptedKeyBytes);

			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(kekAlgorithm);
			v.add(new DEROctetString(iv));

			AlgorithmIdentifier keyEncryptionAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_alg_PWRI_KEK, new DERSequence(v));

			return new RecipientInfo(new PasswordRecipientInfo(keyDerivationAlgorithm, keyEncryptionAlgorithm, encryptedKey));
		}

		public abstract byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize);

		public abstract byte[] generateEncryptedBytes(AlgorithmIdentifier algorithm, byte[] derivedKey, GenericKey contentEncryptionKey);
	}
}