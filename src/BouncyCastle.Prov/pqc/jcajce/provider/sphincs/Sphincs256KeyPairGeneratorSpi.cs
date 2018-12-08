using org.bouncycastle.asn1.nist;

namespace org.bouncycastle.pqc.jcajce.provider.sphincs
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using SHA3Digest = org.bouncycastle.crypto.digests.SHA3Digest;
	using SHA512tDigest = org.bouncycastle.crypto.digests.SHA512tDigest;
	using SPHINCS256KeyGenerationParameters = org.bouncycastle.pqc.crypto.sphincs.SPHINCS256KeyGenerationParameters;
	using SPHINCS256KeyPairGenerator = org.bouncycastle.pqc.crypto.sphincs.SPHINCS256KeyPairGenerator;
	using SPHINCSPrivateKeyParameters = org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
	using SPHINCSPublicKeyParameters = org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
	using SPHINCS256KeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;

	public class Sphincs256KeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		internal ASN1ObjectIdentifier treeDigest = NISTObjectIdentifiers_Fields.id_sha512_256;

		internal SPHINCS256KeyGenerationParameters param;
		internal SPHINCS256KeyPairGenerator engine = new SPHINCS256KeyPairGenerator();

		internal SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
		internal bool initialised = false;

		public Sphincs256KeyPairGeneratorSpi() : base("SPHINCS256")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			throw new IllegalArgumentException("use AlgorithmParameterSpec");
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (!(@params is SPHINCS256KeyGenParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("parameter object not a SPHINCS256KeyGenParameterSpec");
			}

			SPHINCS256KeyGenParameterSpec sphincsParams = (SPHINCS256KeyGenParameterSpec)@params;

			if (sphincsParams.getTreeDigest().Equals(SPHINCS256KeyGenParameterSpec.SHA512_256))
			{
				treeDigest = NISTObjectIdentifiers_Fields.id_sha512_256;
				param = new SPHINCS256KeyGenerationParameters(random, new SHA512tDigest(256));
			}
			else if (sphincsParams.getTreeDigest().Equals(SPHINCS256KeyGenParameterSpec.SHA3_256))
			{
				treeDigest = NISTObjectIdentifiers_Fields.id_sha3_256;
				param = new SPHINCS256KeyGenerationParameters(random, new SHA3Digest(256));
			}

			engine.init(param);
			initialised = true;
		}

		public virtual KeyPair generateKeyPair()
		{
			if (!initialised)
			{
				param = new SPHINCS256KeyGenerationParameters(random, new SHA512tDigest(256));

				engine.init(param);
				initialised = true;
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			SPHINCSPublicKeyParameters pub = (SPHINCSPublicKeyParameters)pair.getPublic();
			SPHINCSPrivateKeyParameters priv = (SPHINCSPrivateKeyParameters)pair.getPrivate();

			return new KeyPair(new BCSphincs256PublicKey(treeDigest, pub), new BCSphincs256PrivateKey(treeDigest, priv));
		}
	}

}