using System;

namespace org.bouncycastle.@operator.jcajce
{

	using GenericHybridParameters = org.bouncycastle.asn1.cms.GenericHybridParameters;
	using RsaKemParameters = org.bouncycastle.asn1.cms.RsaKemParameters;
	using ISOIECObjectIdentifiers = org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using DEROtherInfo = org.bouncycastle.crypto.util.DEROtherInfo;
	using KTSParameterSpec = org.bouncycastle.jcajce.spec.KTSParameterSpec;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using Arrays = org.bouncycastle.util.Arrays;

	public class JceKTSKeyWrapper : AsymmetricKeyWrapper
	{
		private readonly string symmetricWrappingAlg;
		private readonly int keySizeInBits;
		private readonly byte[] partyUInfo;
		private readonly byte[] partyVInfo;

		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private PublicKey publicKey;
		private SecureRandom random;

		public JceKTSKeyWrapper(PublicKey publicKey, string symmetricWrappingAlg, int keySizeInBits, byte[] partyUInfo, byte[] partyVInfo) : base(new AlgorithmIdentifier(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.id_rsa_KEM, new GenericHybridParameters(new AlgorithmIdentifier(org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers_Fields.id_kem_rsa, new RsaKemParameters(new AlgorithmIdentifier(org.bouncycastle.asn1.x9.X9ObjectIdentifiers_Fields.id_kdf_kdf3, new AlgorithmIdentifier(org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha256)), (keySizeInBits + 7) / 8)), JceSymmetricKeyWrapper.determineKeyEncAlg(symmetricWrappingAlg, keySizeInBits))))
		{

			this.publicKey = publicKey;
			this.symmetricWrappingAlg = symmetricWrappingAlg;
			this.keySizeInBits = keySizeInBits;
			this.partyUInfo = Arrays.clone(partyUInfo);
			this.partyVInfo = Arrays.clone(partyVInfo);
		}

		public JceKTSKeyWrapper(X509Certificate certificate, string symmetricWrappingAlg, int keySizeInBits, byte[] partyUInfo, byte[] partyVInfo) : this(certificate.getPublicKey(), symmetricWrappingAlg, keySizeInBits, partyUInfo, partyVInfo)
		{
		}

		public virtual JceKTSKeyWrapper setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JceKTSKeyWrapper setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public virtual JceKTSKeyWrapper setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public override byte[] generateWrappedKey(GenericKey encryptionKey)
		{
			Cipher keyEncryptionCipher = helper.createAsymmetricWrapper(getAlgorithmIdentifier().getAlgorithm(), new HashMap());

			try
			{
				DEROtherInfo otherInfo = (new DEROtherInfo.Builder(JceSymmetricKeyWrapper.determineKeyEncAlg(symmetricWrappingAlg, keySizeInBits), partyUInfo, partyVInfo)).build();
				KTSParameterSpec ktsSpec = (new KTSParameterSpec.Builder(symmetricWrappingAlg, keySizeInBits, otherInfo.getEncoded())).build();

				keyEncryptionCipher.init(Cipher.WRAP_MODE, publicKey, ktsSpec, random);

				return keyEncryptionCipher.wrap(OperatorUtils.getJceKey(encryptionKey));
			}
			catch (Exception e)
			{
				throw new OperatorException("Unable to wrap contents key: " + e.Message, e);
			}
		}
	}

}