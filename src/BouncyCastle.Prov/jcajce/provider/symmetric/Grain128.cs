namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using Grain128Engine = org.bouncycastle.crypto.engines.Grain128Engine;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseStreamCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class Grain128
	{
		private Grain128()
		{
		}

		public class Base : BaseStreamCipher
		{
			public Base() : base(new Grain128Engine(), 12)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("Grain128", 128, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Grain128).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Cipher.Grain128", PREFIX + "$Base");
				provider.addAlgorithm("KeyGenerator.Grain128", PREFIX + "$KeyGen");
			}
		}
	}

}