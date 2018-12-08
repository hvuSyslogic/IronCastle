using org.bouncycastle.cms.bc;

namespace org.bouncycastle.cms.bc
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using StreamCipher = org.bouncycastle.crypto.StreamCipher;
	using CipherOutputStream = org.bouncycastle.crypto.io.CipherOutputStream;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using Integers = org.bouncycastle.util.Integers;

	public class BcCMSContentEncryptorBuilder
	{
		private static Map keySizes = new HashMap();

		static BcCMSContentEncryptorBuilder()
		{
			keySizes.put(CMSAlgorithm.AES128_CBC, Integers.valueOf(128));
			keySizes.put(CMSAlgorithm.AES192_CBC, Integers.valueOf(192));
			keySizes.put(CMSAlgorithm.AES256_CBC, Integers.valueOf(256));

			keySizes.put(CMSAlgorithm.CAMELLIA128_CBC, Integers.valueOf(128));
			keySizes.put(CMSAlgorithm.CAMELLIA192_CBC, Integers.valueOf(192));
			keySizes.put(CMSAlgorithm.CAMELLIA256_CBC, Integers.valueOf(256));
		}

		private static int getKeySize(ASN1ObjectIdentifier oid)
		{
			int? size = (int?)keySizes.get(oid);

			if (size != null)
			{
				return size.Value;
			}

			return -1;
		}

		private readonly ASN1ObjectIdentifier encryptionOID;
		private readonly int keySize;

		private EnvelopedDataHelper helper = new EnvelopedDataHelper();
		private SecureRandom random;

		public BcCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID) : this(encryptionOID, getKeySize(encryptionOID))
		{
		}

		public BcCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize)
		{
			this.encryptionOID = encryptionOID;
			this.keySize = keySize;
		}

		public virtual BcCMSContentEncryptorBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public virtual OutputEncryptor build()
		{
			return new CMSOutputEncryptor(this, encryptionOID, keySize, random);
		}

		public class CMSOutputEncryptor : OutputEncryptor
		{
			private readonly BcCMSContentEncryptorBuilder outerInstance;

			internal KeyParameter encKey;
			internal AlgorithmIdentifier algorithmIdentifier;
			internal object cipher;

			public CMSOutputEncryptor(BcCMSContentEncryptorBuilder outerInstance, ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
			{
				this.outerInstance = outerInstance;
				if (random == null)
				{
					random = new SecureRandom();
				}

				CipherKeyGenerator keyGen = outerInstance.helper.createKeyGenerator(encryptionOID, random);

				encKey = new KeyParameter(keyGen.generateKey());

				algorithmIdentifier = outerInstance.helper.generateAlgorithmIdentifier(encryptionOID, encKey, random);

				cipher = EnvelopedDataHelper.createContentCipher(true, encKey, algorithmIdentifier);
			}

			public virtual AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return algorithmIdentifier;
			}

			public virtual OutputStream getOutputStream(OutputStream dOut)
			{
				if (cipher is BufferedBlockCipher)
				{
					return new CipherOutputStream(dOut, (BufferedBlockCipher)cipher);
				}
				else
				{
					return new CipherOutputStream(dOut, (StreamCipher)cipher);
				}
			}

			public virtual GenericKey getKey()
			{
				return new GenericKey(algorithmIdentifier, encKey.getKey());
			}
		}
	}

}