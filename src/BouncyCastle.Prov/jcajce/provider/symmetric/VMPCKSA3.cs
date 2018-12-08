namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using VMPCKSA3Engine = org.bouncycastle.crypto.engines.VMPCKSA3Engine;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseStreamCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class VMPCKSA3
	{
		private VMPCKSA3()
		{
		}

		public class Base : BaseStreamCipher
		{
			public Base() : base(new VMPCKSA3Engine(), 16)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("VMPC-KSA3", 128, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(VMPCKSA3).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.VMPC-KSA3", PREFIX + "$Base");
				provider.addAlgorithm("KeyGenerator.VMPC-KSA3", PREFIX + "$KeyGen");

			}
		}
	}

}