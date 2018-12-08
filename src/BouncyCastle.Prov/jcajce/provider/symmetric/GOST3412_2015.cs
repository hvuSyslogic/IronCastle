namespace org.bouncycastle.jcajce.provider.symmetric
{
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using GOST3412_2015Engine = org.bouncycastle.crypto.engines.GOST3412_2015Engine;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using G3413CBCBlockCipher = org.bouncycastle.crypto.modes.G3413CBCBlockCipher;
	using G3413CFBBlockCipher = org.bouncycastle.crypto.modes.G3413CFBBlockCipher;
	using G3413CTRBlockCipher = org.bouncycastle.crypto.modes.G3413CTRBlockCipher;
	using G3413OFBBlockCipher = org.bouncycastle.crypto.modes.G3413OFBBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;


	public class GOST3412_2015
	{
		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new GOST3412_2015Engine())
			{
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new G3413CBCBlockCipher(new GOST3412_2015Engine()), false, 128)
			{
			}
		}

		public class GCFB : BaseBlockCipher
		{
			public GCFB() : base(new BufferedBlockCipher(new G3413CFBBlockCipher(new GOST3412_2015Engine())), false, 128)
			{
			}
		}

		public class GCFB8 : BaseBlockCipher
		{
			public GCFB8() : base(new BufferedBlockCipher(new G3413CFBBlockCipher(new GOST3412_2015Engine(), 8)), false, 128)
			{
			}
		}

		public class OFB : BaseBlockCipher
		{
			public OFB() : base(new BufferedBlockCipher(new G3413OFBBlockCipher(new GOST3412_2015Engine())), false, 128)
			{
			}

		}

		public class CTR : BaseBlockCipher
		{
			public CTR() : base(new BufferedBlockCipher(new G3413CTRBlockCipher(new GOST3412_2015Engine())), 128)
			{
			}

		}

		/// <summary>
		/// GOST3412 2015 CMAC( OMAC1)
		/// </summary>
		public class Mac : BaseMac
		{
			public Mac() : base(new CMac(new GOST3412_2015Engine()))
			{
			}
		}


		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : this(256)
			{
			}

			public KeyGen(int keySize) : base("GOST3412-2015", keySize, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(GOST3412_2015).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Cipher.GOST3412-2015", PREFIX + "$ECB");
				provider.addAlgorithm("Cipher.GOST3412-2015/CFB", PREFIX + "$GCFB");
				provider.addAlgorithm("Cipher.GOST3412-2015/CFB8", PREFIX + "$GCFB8");
				provider.addAlgorithm("Cipher.GOST3412-2015/OFB", PREFIX + "$OFB");
				provider.addAlgorithm("Cipher.GOST3412-2015/CBC", PREFIX + "$CBC");
				provider.addAlgorithm("Cipher.GOST3412-2015/CTR", PREFIX + "$CTR");

				provider.addAlgorithm("KeyGenerator.GOST3412-2015", PREFIX + "$KeyGen");

				provider.addAlgorithm("Mac.GOST3412MAC", PREFIX + "$Mac");
				provider.addAlgorithm("Alg.Alias.Mac.GOST3412-2015", "GOST3412MAC");
			}
		}


	}

}