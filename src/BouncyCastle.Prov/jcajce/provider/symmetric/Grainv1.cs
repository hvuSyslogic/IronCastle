namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using Grainv1Engine = org.bouncycastle.crypto.engines.Grainv1Engine;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseStreamCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class Grainv1
	{
		private Grainv1()
		{
		}

		public class Base : BaseStreamCipher
		{
			public Base() : base(new Grainv1Engine(), 8)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("Grainv1", 80, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Grainv1).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Cipher.Grainv1", PREFIX + "$Base");
				provider.addAlgorithm("KeyGenerator.Grainv1", PREFIX + "$KeyGen");
			}
		}
	}

}