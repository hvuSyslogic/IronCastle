using org.bouncycastle.asn1.misc;

namespace org.bouncycastle.jcajce.provider.symmetric
{
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using BlowfishEngine = org.bouncycastle.crypto.engines.BlowfishEngine;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class Blowfish
	{
		private Blowfish()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new BlowfishEngine())
			{
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new BlowfishEngine()), 64)
			{
			}
		}

		public class CMAC : BaseMac
		{
			public CMAC() : base(new CMac(new BlowfishEngine()))
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("Blowfish", 128, new CipherKeyGenerator())
			{
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "Blowfish IV";
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Blowfish).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Mac.BLOWFISHCMAC", PREFIX + "$CMAC");
				provider.addAlgorithm("Cipher.BLOWFISH", PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", MiscObjectIdentifiers_Fields.cryptlib_algorithm_blowfish_CBC, PREFIX + "$CBC");
				provider.addAlgorithm("KeyGenerator.BLOWFISH", PREFIX + "$KeyGen");
				provider.addAlgorithm("Alg.Alias.KeyGenerator", MiscObjectIdentifiers_Fields.cryptlib_algorithm_blowfish_CBC, "BLOWFISH");
				provider.addAlgorithm("AlgorithmParameters.BLOWFISH", PREFIX + "$AlgParams");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters", MiscObjectIdentifiers_Fields.cryptlib_algorithm_blowfish_CBC, "BLOWFISH");

			}
		}
	}

}