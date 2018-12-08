using org.bouncycastle.asn1.gnu;

namespace org.bouncycastle.jcajce.provider.symmetric
{
	using GNUObjectIdentifiers = org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using SerpentEngine = org.bouncycastle.crypto.engines.SerpentEngine;
	using TnepresEngine = org.bouncycastle.crypto.engines.TnepresEngine;
	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
	using GMac = org.bouncycastle.crypto.macs.GMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using CFBBlockCipher = org.bouncycastle.crypto.modes.CFBBlockCipher;
	using GCMBlockCipher = org.bouncycastle.crypto.modes.GCMBlockCipher;
	using OFBBlockCipher = org.bouncycastle.crypto.modes.OFBBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BlockCipherProvider = org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

	public sealed class Serpent
	{
		private Serpent()
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
					return new SerpentEngine();
				}
			}
		}

		public class TECB : BaseBlockCipher
		{
			public TECB() : base(new BlockCipherProviderAnonymousInnerClass())
			{
			}

			public class BlockCipherProviderAnonymousInnerClass : BlockCipherProvider
			{
				public BlockCipher get()
				{
					return new TnepresEngine();
				}
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new SerpentEngine()), 128)
			{
			}
		}

		public class CFB : BaseBlockCipher
		{
			public CFB() : base(new BufferedBlockCipher(new CFBBlockCipher(new SerpentEngine(), 128)), 128)
			{
			}
		}

		public class OFB : BaseBlockCipher
		{
			public OFB() : base(new BufferedBlockCipher(new OFBBlockCipher(new SerpentEngine(), 128)), 128)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("Serpent", 192, new CipherKeyGenerator())
			{
			}
		}

		public class TKeyGen : BaseKeyGenerator
		{
			public TKeyGen() : base("Tnepres", 192, new CipherKeyGenerator())
			{
			}
		}

		public class SerpentGMAC : BaseMac
		{
			public SerpentGMAC() : base(new GMac(new GCMBlockCipher(new SerpentEngine())))
			{
			}
		}

		public class TSerpentGMAC : BaseMac
		{
			public TSerpentGMAC() : base(new GMac(new GCMBlockCipher(new TnepresEngine())))
			{
			}
		}

		public class Poly1305 : BaseMac
		{
			public Poly1305() : base(new org.bouncycastle.crypto.macs.Poly1305(new SerpentEngine()))
			{
			}
		}

		public class Poly1305KeyGen : BaseKeyGenerator
		{
			public Poly1305KeyGen() : base("Poly1305-Serpent", 256, new Poly1305KeyGenerator())
			{
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "Serpent IV";
			}
		}

		public class TAlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "Tnepres IV";
			}
		}

		public class Mappings : SymmetricAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Serpent).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.Serpent", PREFIX + "$ECB");
				provider.addAlgorithm("KeyGenerator.Serpent", PREFIX + "$KeyGen");
				provider.addAlgorithm("AlgorithmParameters.Serpent", PREFIX + "$AlgParams");

				provider.addAlgorithm("Cipher.Tnepres", PREFIX + "$TECB");
				provider.addAlgorithm("KeyGenerator.Tnepres", PREFIX + "$TKeyGen");
				provider.addAlgorithm("AlgorithmParameters.Tnepres", PREFIX + "$TAlgParams");

				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_128_ECB, PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_192_ECB, PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_256_ECB, PREFIX + "$ECB");

				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_128_CBC, PREFIX + "$CBC");
				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_192_CBC, PREFIX + "$CBC");
				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_256_CBC, PREFIX + "$CBC");

				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_128_CFB, PREFIX + "$CFB");
				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_192_CFB, PREFIX + "$CFB");
				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_256_CFB, PREFIX + "$CFB");

				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_128_OFB, PREFIX + "$OFB");
				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_192_OFB, PREFIX + "$OFB");
				provider.addAlgorithm("Cipher", GNUObjectIdentifiers_Fields.Serpent_256_OFB, PREFIX + "$OFB");

				addGMacAlgorithm(provider, "SERPENT", PREFIX + "$SerpentGMAC", PREFIX + "$KeyGen");
				addGMacAlgorithm(provider, "TNEPRES", PREFIX + "$TSerpentGMAC", PREFIX + "$TKeyGen");
				addPoly1305Algorithm(provider, "SERPENT", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
			}
		}
	}

}