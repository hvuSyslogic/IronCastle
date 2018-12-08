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
	using XMSSMTKeyGenerationParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyGenerationParameters;
	using XMSSMTKeyPairGenerator = org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator;
	using XMSSMTParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
	using XMSSMTPrivateKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
	using XMSSMTPublicKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
	using XMSSMTParameterSpec = org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
	using XMSSParameterSpec = org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

	public class XMSSMTKeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		private XMSSMTKeyGenerationParameters param;
		private XMSSMTKeyPairGenerator engine = new XMSSMTKeyPairGenerator();
		private ASN1ObjectIdentifier treeDigest;

		private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
		private bool initialised = false;

		public XMSSMTKeyPairGeneratorSpi() : base("XMSSMT")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			throw new IllegalArgumentException("use AlgorithmParameterSpec");
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (!(@params is XMSSMTParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("parameter object not a XMSSMTParameterSpec");
			}

			XMSSMTParameterSpec xmssParams = (XMSSMTParameterSpec)@params;

			if (xmssParams.getTreeDigest().Equals(XMSSParameterSpec.SHA256))
			{
				treeDigest = NISTObjectIdentifiers_Fields.id_sha256;
				param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHA256Digest()), random);
			}
			else if (xmssParams.getTreeDigest().Equals(XMSSParameterSpec.SHA512))
			{
				treeDigest = NISTObjectIdentifiers_Fields.id_sha512;
				param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHA512Digest()), random);
			}
			else if (xmssParams.getTreeDigest().Equals(XMSSParameterSpec.SHAKE128))
			{
				treeDigest = NISTObjectIdentifiers_Fields.id_shake128;
				param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHAKEDigest(128)), random);
			}
			else if (xmssParams.getTreeDigest().Equals(XMSSParameterSpec.SHAKE256))
			{
				treeDigest = NISTObjectIdentifiers_Fields.id_shake256;
				param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHAKEDigest(256)), random);
			}

			engine.init(param);
			initialised = true;
		}

		public virtual KeyPair generateKeyPair()
		{
			if (!initialised)
			{
				param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(10, 20, new SHA512Digest()), random);

				engine.init(param);
				initialised = true;
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			XMSSMTPublicKeyParameters pub = (XMSSMTPublicKeyParameters)pair.getPublic();
			XMSSMTPrivateKeyParameters priv = (XMSSMTPrivateKeyParameters)pair.getPrivate();

			return new KeyPair(new BCXMSSMTPublicKey(treeDigest, pub), new BCXMSSMTPrivateKey(treeDigest, priv));
		}
	}

}