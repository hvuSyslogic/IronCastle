namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class SipHash
	{
		private SipHash()
		{
		}

		public class Mac24 : BaseMac
		{
			public Mac24() : base(new org.bouncycastle.crypto.macs.SipHash())
			{
			}
		}

		public class Mac48 : BaseMac
		{
			public Mac48() : base(new org.bouncycastle.crypto.macs.SipHash(4, 8))
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("SipHash", 128, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(SipHash).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Mac.SIPHASH-2-4", PREFIX + "$Mac24");
				provider.addAlgorithm("Alg.Alias.Mac.SIPHASH", "SIPHASH-2-4");
				provider.addAlgorithm("Mac.SIPHASH-4-8", PREFIX + "$Mac48");

				provider.addAlgorithm("KeyGenerator.SIPHASH", PREFIX + "$KeyGen");
				provider.addAlgorithm("Alg.Alias.KeyGenerator.SIPHASH-2-4", "SIPHASH");
				provider.addAlgorithm("Alg.Alias.KeyGenerator.SIPHASH-4-8", "SIPHASH");
			}
		}
	}

}