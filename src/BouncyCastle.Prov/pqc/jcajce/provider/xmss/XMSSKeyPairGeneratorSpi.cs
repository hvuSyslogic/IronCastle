using org.bouncycastle.asn1.nist;

namespace org.bouncycastle.pqc.jcajce.provider.xmss
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using SHAKEDigest = org.bouncycastle.crypto.digests.SHAKEDigest;
	using XMSSKeyGenerationParameters = org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters;
	using XMSSKeyPairGenerator = org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator;
	using XMSSParameters = org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
	using XMSSPrivateKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
	using XMSSPublicKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
	using XMSSParameterSpec = org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

	public class XMSSKeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		private XMSSKeyGenerationParameters param;
		private ASN1ObjectIdentifier treeDigest;
		private XMSSKeyPairGenerator engine = new XMSSKeyPairGenerator();

		private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
		private bool initialised = false;

		public XMSSKeyPairGeneratorSpi() : base("XMSS")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			throw new IllegalArgumentException("use AlgorithmParameterSpec");
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (!(@params is XMSSParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("parameter object not a XMSSParameterSpec");
			}

			XMSSParameterSpec xmssParams = (XMSSParameterSpec)@params;

			if (xmssParams.getTreeDigest().Equals(XMSSParameterSpec.SHA256))
			{
				treeDigest = NISTObjectIdentifiers_Fields.id_sha256;
				param = new XMSSKeyGenerationParameters(new XMSSParameters(xmssParams.getHeight(), new SHA256Digest()), random);
			}
			else if (xmssParams.getTreeDigest().Equals(XMSSParameterSpec.SHA512))
			{
				treeDigest = NISTObjectIdentifiers_Fields.id_sha512;
				param = new XMSSKeyGenerationParameters(new XMSSParameters(xmssParams.getHeight(), new SHA512Digest()), random);
			}
			else if (xmssParams.getTreeDigest().Equals(XMSSParameterSpec.SHAKE128))
			{
				treeDigest = NISTObjectIdentifiers_Fields.id_shake128;
				param = new XMSSKeyGenerationParameters(new XMSSParameters(xmssParams.getHeight(), new SHAKEDigest(128)), random);
			}
			else if (xmssParams.getTreeDigest().Equals(XMSSParameterSpec.SHAKE256))
			{
				treeDigest = NISTObjectIdentifiers_Fields.id_shake256;
				param = new XMSSKeyGenerationParameters(new XMSSParameters(xmssParams.getHeight(), new SHAKEDigest(256)), random);
			}

			engine.init(param);
			initialised = true;
		}

		public virtual KeyPair generateKeyPair()
		{
			if (!initialised)
			{
				param = new XMSSKeyGenerationParameters(new XMSSParameters(10, new SHA512Digest()), random);

				engine.init(param);
				initialised = true;
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			XMSSPublicKeyParameters pub = (XMSSPublicKeyParameters)pair.getPublic();
			XMSSPrivateKeyParameters priv = (XMSSPrivateKeyParameters)pair.getPrivate();

			return new KeyPair(new BCXMSSPublicKey(treeDigest, pub), new BCXMSSPrivateKey(treeDigest, priv));
		}
	}

}