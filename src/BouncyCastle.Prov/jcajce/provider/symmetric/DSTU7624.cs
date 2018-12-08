using org.bouncycastle.asn1.ua;

using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using UAObjectIdentifiers = org.bouncycastle.asn1.ua.UAObjectIdentifiers;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using DSTU7624Engine = org.bouncycastle.crypto.engines.DSTU7624Engine;
	using DSTU7624WrapEngine = org.bouncycastle.crypto.engines.DSTU7624WrapEngine;
	using KGMac = org.bouncycastle.crypto.macs.KGMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using CFBBlockCipher = org.bouncycastle.crypto.modes.CFBBlockCipher;
	using KCCMBlockCipher = org.bouncycastle.crypto.modes.KCCMBlockCipher;
	using KCTRBlockCipher = org.bouncycastle.crypto.modes.KCTRBlockCipher;
	using KGCMBlockCipher = org.bouncycastle.crypto.modes.KGCMBlockCipher;
	using OFBBlockCipher = org.bouncycastle.crypto.modes.OFBBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameterGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BaseWrapCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
	using BlockCipherProvider = org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

	public class DSTU7624
	{
		private DSTU7624()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new BlockCipherProviderAnonymousInnerClass())
			{
			}

			public class BlockCipherProviderAnonymousInnerClass : BlockCipherProvider
			{
				public BlockCipher get()
				{
					return new DSTU7624Engine(128);
				}
			}
		}

		// these next three allow some variation on the keysize used in each case.
		public class ECB_128 : BaseBlockCipher
		{
			public ECB_128() : base(new DSTU7624Engine(128))
			{
			}
		}

		public class ECB_256 : BaseBlockCipher
		{
			public ECB_256() : base(new DSTU7624Engine(256))
			{
			}
		}

		public class ECB_512 : BaseBlockCipher
		{
			public ECB_512() : base(new DSTU7624Engine(512))
			{
			}
		}

		// what follows is fixed with a key size the same as the block size.
		public class ECB128 : BaseBlockCipher
		{
			public ECB128() : base(new DSTU7624Engine(128))
			{ // TODO: key size is also meant to be fixed
			}
		}

		public class ECB256 : BaseBlockCipher
		{
			public ECB256() : base(new DSTU7624Engine(256))
			{
			}
		}

		public class ECB512 : BaseBlockCipher
		{
			public ECB512() : base(new DSTU7624Engine(512))
			{
			}
		}

		public class CBC128 : BaseBlockCipher
		{
			public CBC128() : base(new CBCBlockCipher(new DSTU7624Engine(128)), 128)
			{ // TODO: key size is also meant to be fixed
			}
		}

		public class CBC256 : BaseBlockCipher
		{
			public CBC256() : base(new CBCBlockCipher(new DSTU7624Engine(256)), 256)
			{
			}
		}

		public class CBC512 : BaseBlockCipher
		{
			public CBC512() : base(new CBCBlockCipher(new DSTU7624Engine(512)), 512)
			{
			}
		}

		public class OFB128 : BaseBlockCipher
		{
			public OFB128() : base(new BufferedBlockCipher(new OFBBlockCipher(new DSTU7624Engine(128), 128)), 128)
			{ // TODO: key size is also meant to be fixed
			}
		}

		public class OFB256 : BaseBlockCipher
		{
			public OFB256() : base(new BufferedBlockCipher(new OFBBlockCipher(new DSTU7624Engine(256), 256)), 256)
			{
			}
		}

		public class OFB512 : BaseBlockCipher
		{
			public OFB512() : base(new BufferedBlockCipher(new OFBBlockCipher(new DSTU7624Engine(512), 512)), 512)
			{
			}
		}

		public class CFB128 : BaseBlockCipher
		{
			public CFB128() : base(new BufferedBlockCipher(new CFBBlockCipher(new DSTU7624Engine(128), 128)), 128)
			{ // TODO: key size is also meant to be fixed
			}
		}

		public class CFB256 : BaseBlockCipher
		{
			public CFB256() : base(new BufferedBlockCipher(new CFBBlockCipher(new DSTU7624Engine(256), 256)), 256)
			{
			}
		}

		public class CFB512 : BaseBlockCipher
		{
			public CFB512() : base(new BufferedBlockCipher(new CFBBlockCipher(new DSTU7624Engine(512), 512)), 512)
			{
			}
		}

		public class CTR128 : BaseBlockCipher
		{
			public CTR128() : base(new BufferedBlockCipher(new KCTRBlockCipher(new DSTU7624Engine(128))), 128)
			{ // TODO: key size is also meant to be fixed
			}
		}

		public class CTR256 : BaseBlockCipher
		{
			public CTR256() : base(new BufferedBlockCipher(new KCTRBlockCipher(new DSTU7624Engine(256))), 256)
			{
			}
		}

		public class CTR512 : BaseBlockCipher
		{
			public CTR512() : base(new BufferedBlockCipher(new KCTRBlockCipher(new DSTU7624Engine(512))), 512)
			{
			}
		}

		public class CCM128 : BaseBlockCipher
		{
			public CCM128() : base(new KCCMBlockCipher(new DSTU7624Engine(128)))
			{ // TODO: key size is also meant to be fixed
			}
		}

		public class CCM256 : BaseBlockCipher
		{
			public CCM256() : base(new KCCMBlockCipher(new DSTU7624Engine(256)))
			{
			}
		}

		public class CCM512 : BaseBlockCipher
		{
			public CCM512() : base(new KCCMBlockCipher(new DSTU7624Engine(512)))
			{
			}
		}

		public class GCM128 : BaseBlockCipher
		{
			public GCM128() : base(new KGCMBlockCipher(new DSTU7624Engine(128)))
			{ // TODO: key size is also meant to be fixed
			}
		}

		public class GCM256 : BaseBlockCipher
		{
			public GCM256() : base(new KGCMBlockCipher(new DSTU7624Engine(256)))
			{
			}
		}

		public class GCM512 : BaseBlockCipher
		{
			public GCM512() : base(new KGCMBlockCipher(new DSTU7624Engine(512)))
			{
			}
		}

		public class Wrap : BaseWrapCipher
		{
			public Wrap() : base(new DSTU7624WrapEngine(128))
			{
			}
		}

		public class Wrap128 : BaseWrapCipher
		{
			public Wrap128() : base(new DSTU7624WrapEngine(128))
			{
			}
		}

		public class Wrap256 : BaseWrapCipher
		{
			public Wrap256() : base(new DSTU7624WrapEngine(256))
			{
			}
		}

		public class Wrap512 : BaseWrapCipher
		{
			public Wrap512() : base(new DSTU7624WrapEngine(512))
			{
			}
		}

		public class GMAC : BaseMac
		{
			public GMAC() : base(new KGMac(new KGCMBlockCipher(new DSTU7624Engine(128)), 128))
			{
			}
		}
		   // TODO: enforce key size restriction
		public class GMAC128 : BaseMac
		{
			public GMAC128() : base(new KGMac(new KGCMBlockCipher(new DSTU7624Engine(128)), 128))
			{
			}
		}

		public class GMAC256 : BaseMac
		{
			public GMAC256() : base(new KGMac(new KGCMBlockCipher(new DSTU7624Engine(256)), 256))
			{
			}
		}

		public class GMAC512 : BaseMac
		{
			public GMAC512() : base(new KGMac(new KGCMBlockCipher(new DSTU7624Engine(512)), 512))
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : this(256)
			{
			}

			public KeyGen(int keySize) : base("DSTU7624", keySize, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGen128 : DSTU7624.KeyGen
		{
			public KeyGen128() : base(128)
			{
			}
		}

		public class KeyGen256 : DSTU7624.KeyGen
		{
			public KeyGen256() : base(256)
			{
			}
		}

		public class KeyGen512 : DSTU7624.KeyGen
		{
			public KeyGen512() : base(512)
			{
			}
		}

		public class AlgParamGen : BaseAlgorithmParameterGenerator
		{
			internal readonly int ivLength;

			public AlgParamGen(int blockSize)
			{
				this.ivLength = blockSize / 8;
			}

			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for DSTU7624 parameter generation.");
			}

			public virtual AlgorithmParameters engineGenerateParameters()
			{
				byte[] iv = new byte[ivLength];

				if (random == null)
				{
					random = CryptoServicesRegistrar.getSecureRandom();
				}

				random.nextBytes(iv);

				AlgorithmParameters @params;

				try
				{
					@params = createParametersInstance("DSTU7624");
					@params.init(new IvParameterSpec(iv));
				}
				catch (Exception e)
				{
					throw new RuntimeException(e.Message);
				}

				return @params;
			}
		}

		public class AlgParamGen128 : AlgParamGen
		{
			public AlgParamGen128() : base(128)
			{
			}
		}

		public class AlgParamGen256 : AlgParamGen
		{
			public AlgParamGen256() : base(256)
			{
			}
		}

		public class AlgParamGen512 : AlgParamGen
		{
			public AlgParamGen512() : base(512)
			{
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "DSTU7624 IV";
			}
		}

		public class Mappings : SymmetricAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(DSTU7624).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("AlgorithmParameters.DSTU7624", PREFIX + "$AlgParams128");
				provider.addAlgorithm("AlgorithmParameters", UAObjectIdentifiers_Fields.dstu7624cbc_128, PREFIX + "$AlgParams");
				provider.addAlgorithm("AlgorithmParameters", UAObjectIdentifiers_Fields.dstu7624cbc_256, PREFIX + "$AlgParams");
				provider.addAlgorithm("AlgorithmParameters", UAObjectIdentifiers_Fields.dstu7624cbc_512, PREFIX + "$AlgParams");

				provider.addAlgorithm("AlgorithmParameterGenerator.DSTU7624", PREFIX + "$AlgParamGen128");
				provider.addAlgorithm("AlgorithmParameterGenerator", UAObjectIdentifiers_Fields.dstu7624cbc_128, PREFIX + "$AlgParamGen128");
				provider.addAlgorithm("AlgorithmParameterGenerator", UAObjectIdentifiers_Fields.dstu7624cbc_256, PREFIX + "$AlgParamGen256");
				provider.addAlgorithm("AlgorithmParameterGenerator", UAObjectIdentifiers_Fields.dstu7624cbc_512, PREFIX + "$AlgParamGen512");

				provider.addAlgorithm("Cipher.DSTU7624", PREFIX + "$ECB_128");
				provider.addAlgorithm("Cipher.DSTU7624-128", PREFIX + "$ECB_128");
				provider.addAlgorithm("Cipher.DSTU7624-256", PREFIX + "$ECB_256");
				provider.addAlgorithm("Cipher.DSTU7624-512", PREFIX + "$ECB_512");

				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ecb_128, PREFIX + "$ECB128");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ecb_256, PREFIX + "$ECB256");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ecb_512, PREFIX + "$ECB512");

				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624cbc_128, PREFIX + "$CBC128");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624cbc_256, PREFIX + "$CBC256");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624cbc_512, PREFIX + "$CBC512");

				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ofb_128, PREFIX + "$OFB128");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ofb_256, PREFIX + "$OFB256");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ofb_512, PREFIX + "$OFB512");

				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624cfb_128, PREFIX + "$CFB128");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624cfb_256, PREFIX + "$CFB256");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624cfb_512, PREFIX + "$CFB512");

				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ctr_128, PREFIX + "$CTR128");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ctr_256, PREFIX + "$CTR256");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ctr_512, PREFIX + "$CTR512");

				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ccm_128, PREFIX + "$CCM128");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ccm_256, PREFIX + "$CCM256");
				provider.addAlgorithm("Cipher", UAObjectIdentifiers_Fields.dstu7624ccm_512, PREFIX + "$CCM512");

				provider.addAlgorithm("Cipher.DSTU7624KW", PREFIX + "$Wrap");
				provider.addAlgorithm("Alg.Alias.Cipher.DSTU7624WRAP", "DSTU7624KW");
				provider.addAlgorithm("Cipher.DSTU7624-128KW", PREFIX + "$Wrap128");
				provider.addAlgorithm("Alg.Alias.Cipher." + UAObjectIdentifiers_Fields.dstu7624kw_128.getId(), "DSTU7624-128KW");
				provider.addAlgorithm("Alg.Alias.Cipher.DSTU7624-128WRAP", "DSTU7624-128KW");
				provider.addAlgorithm("Cipher.DSTU7624-256KW", PREFIX + "$Wrap256");
				provider.addAlgorithm("Alg.Alias.Cipher." + UAObjectIdentifiers_Fields.dstu7624kw_256.getId(), "DSTU7624-256KW");
				provider.addAlgorithm("Alg.Alias.Cipher.DSTU7624-256WRAP", "DSTU7624-256KW");
				provider.addAlgorithm("Cipher.DSTU7624-512KW", PREFIX + "$Wrap512");
				provider.addAlgorithm("Alg.Alias.Cipher." + UAObjectIdentifiers_Fields.dstu7624kw_512.getId(), "DSTU7624-512KW");
				provider.addAlgorithm("Alg.Alias.Cipher.DSTU7624-512WRAP", "DSTU7624-512KW");

				provider.addAlgorithm("Mac.DSTU7624GMAC", PREFIX + "$GMAC");
				provider.addAlgorithm("Mac.DSTU7624-128GMAC", PREFIX + "$GMAC128");
				provider.addAlgorithm("Alg.Alias.Mac." + UAObjectIdentifiers_Fields.dstu7624gmac_128.getId(), "DSTU7624-128GMAC");
				provider.addAlgorithm("Mac.DSTU7624-256GMAC", PREFIX + "$GMAC256");
				provider.addAlgorithm("Alg.Alias.Mac." + UAObjectIdentifiers_Fields.dstu7624gmac_256.getId(), "DSTU7624-256GMAC");
				provider.addAlgorithm("Mac.DSTU7624-512GMAC", PREFIX + "$GMAC512");
				provider.addAlgorithm("Alg.Alias.Mac." + UAObjectIdentifiers_Fields.dstu7624gmac_512.getId(), "DSTU7624-512GMAC");

				provider.addAlgorithm("KeyGenerator.DSTU7624", PREFIX + "$KeyGen");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624kw_128, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624kw_256, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624kw_512, PREFIX + "$KeyGen512");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ecb_128, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ecb_256, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ecb_512, PREFIX + "$KeyGen512");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624cbc_128, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624cbc_256, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624cbc_512, PREFIX + "$KeyGen512");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ofb_128, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ofb_256, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ofb_512, PREFIX + "$KeyGen512");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624cfb_128, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624cfb_256, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624cfb_512, PREFIX + "$KeyGen512");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ctr_128, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ctr_256, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ctr_512, PREFIX + "$KeyGen512");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ccm_128, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ccm_256, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624ccm_512, PREFIX + "$KeyGen512");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624gmac_128, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624gmac_256, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers_Fields.dstu7624gmac_512, PREFIX + "$KeyGen512");
			}
		}
	}

}