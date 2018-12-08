namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using Salsa20Engine = org.bouncycastle.crypto.engines.Salsa20Engine;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseStreamCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class Salsa20
	{
		private Salsa20()
		{
		}

		public class Base : BaseStreamCipher
		{
			public Base() : base(new Salsa20Engine(), 8)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("Salsa20", 128, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Salsa20).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.SALSA20", PREFIX + "$Base");
				provider.addAlgorithm("KeyGenerator.SALSA20", PREFIX + "$KeyGen");

			}
		}
	}

}