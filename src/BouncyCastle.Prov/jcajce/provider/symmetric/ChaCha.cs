namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using ChaCha7539Engine = org.bouncycastle.crypto.engines.ChaCha7539Engine;
	using ChaChaEngine = org.bouncycastle.crypto.engines.ChaChaEngine;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseStreamCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class ChaCha
	{
		private ChaCha()
		{
		}

		public class Base : BaseStreamCipher
		{
			public Base() : base(new ChaChaEngine(), 8)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("ChaCha", 128, new CipherKeyGenerator())
			{
			}
		}

		public class Base7539 : BaseStreamCipher
		{
			public Base7539() : base(new ChaCha7539Engine(), 12)
			{
			}
		}

		public class KeyGen7539 : BaseKeyGenerator
		{
			public KeyGen7539() : base("ChaCha7539", 256, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(ChaCha).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.CHACHA", PREFIX + "$Base");
				provider.addAlgorithm("KeyGenerator.CHACHA", PREFIX + "$KeyGen");

				provider.addAlgorithm("Cipher.CHACHA7539", PREFIX + "$Base7539");
				provider.addAlgorithm("KeyGenerator.CHACHA7539", PREFIX + "$KeyGen7539");
			}
		}
	}

}