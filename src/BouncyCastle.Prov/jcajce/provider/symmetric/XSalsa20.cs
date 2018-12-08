namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using XSalsa20Engine = org.bouncycastle.crypto.engines.XSalsa20Engine;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseStreamCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class XSalsa20
	{
		private XSalsa20()
		{
		}

		public class Base : BaseStreamCipher
		{
			public Base() : base(new XSalsa20Engine(), 24)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("XSalsa20", 256, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(XSalsa20).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.XSALSA20", PREFIX + "$Base");
				provider.addAlgorithm("KeyGenerator.XSALSA20", PREFIX + "$KeyGen");

			}
		}
	}

}