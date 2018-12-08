namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using VMPCEngine = org.bouncycastle.crypto.engines.VMPCEngine;
	using VMPCMac = org.bouncycastle.crypto.macs.VMPCMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BaseStreamCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class VMPC
	{
		private VMPC()
		{
		}

		public class Base : BaseStreamCipher
		{
			public Base() : base(new VMPCEngine(), 16)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("VMPC", 128, new CipherKeyGenerator())
			{
			}
		}

		public class Mac : BaseMac
		{
			public Mac() : base(new VMPCMac())
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(VMPC).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.VMPC", PREFIX + "$Base");
				provider.addAlgorithm("KeyGenerator.VMPC", PREFIX + "$KeyGen");
				provider.addAlgorithm("Mac.VMPCMAC", PREFIX + "$Mac");
				provider.addAlgorithm("Alg.Alias.Mac.VMPC", "VMPCMAC");
				provider.addAlgorithm("Alg.Alias.Mac.VMPC-MAC", "VMPCMAC");

			}
		}
	}

}