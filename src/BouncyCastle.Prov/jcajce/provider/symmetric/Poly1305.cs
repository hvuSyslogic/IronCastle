namespace org.bouncycastle.jcajce.provider.symmetric
{
	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public class Poly1305
	{
		private Poly1305()
		{
		}

		public class Mac : BaseMac
		{
			public Mac() : base(new org.bouncycastle.crypto.macs.Poly1305())
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("Poly1305", 256, new Poly1305KeyGenerator())
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Poly1305).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Mac.POLY1305", PREFIX + "$Mac");

				provider.addAlgorithm("KeyGenerator.POLY1305", PREFIX + "$KeyGen");
			}
		}
	}

}