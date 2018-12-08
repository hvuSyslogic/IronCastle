namespace org.bouncycastle.jcajce.provider.digest
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using KeccakDigest = org.bouncycastle.crypto.digests.KeccakDigest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class Keccak
	{
		private Keccak()
		{

		}

		public class DigestKeccak : BCMessageDigest, Cloneable
		{
			public DigestKeccak(int size) : base(new KeccakDigest(size))
			{
			}

			public virtual object clone()
			{
				BCMessageDigest d = (BCMessageDigest)base.clone();
				d.digest = new KeccakDigest((KeccakDigest)digest);

				return d;
			}
		}

		public class Digest224 : DigestKeccak
		{
			public Digest224() : base(224)
			{
			}
		}

		public class Digest256 : DigestKeccak
		{
			public Digest256() : base(256)
			{
			}
		}

		public class Digest288 : DigestKeccak
		{
			public Digest288() : base(288)
			{
			}
		}

		public class Digest384 : DigestKeccak
		{
			public Digest384() : base(384)
			{
			}
		}

		public class Digest512 : DigestKeccak
		{
			public Digest512() : base(512)
			{
			}
		}

		public class HashMac224 : BaseMac
		{
			public HashMac224() : base(new HMac(new KeccakDigest(224)))
			{
			}
		}

		public class HashMac256 : BaseMac
		{
			public HashMac256() : base(new HMac(new KeccakDigest(256)))
			{
			}
		}

		public class HashMac288 : BaseMac
		{
			public HashMac288() : base(new HMac(new KeccakDigest(288)))
			{
			}
		}

		public class HashMac384 : BaseMac
		{
			public HashMac384() : base(new HMac(new KeccakDigest(384)))
			{
			}
		}

		public class HashMac512 : BaseMac
		{
			public HashMac512() : base(new HMac(new KeccakDigest(512)))
			{
			}
		}

		public class KeyGenerator224 : BaseKeyGenerator
		{
			public KeyGenerator224() : base("HMACKECCAK224", 224, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGenerator256 : BaseKeyGenerator
		{
			public KeyGenerator256() : base("HMACKECCAK256", 256, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGenerator288 : BaseKeyGenerator
		{
			public KeyGenerator288() : base("HMACKECCAK288", 288, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGenerator384 : BaseKeyGenerator
		{
			public KeyGenerator384() : base("HMACKECCAK384", 384, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGenerator512 : BaseKeyGenerator
		{
			public KeyGenerator512() : base("HMACKECCAK512", 512, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Keccak).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.KECCAK-224", PREFIX + "$Digest224");
				provider.addAlgorithm("MessageDigest.KECCAK-288", PREFIX + "$Digest288");
				provider.addAlgorithm("MessageDigest.KECCAK-256", PREFIX + "$Digest256");
				provider.addAlgorithm("MessageDigest.KECCAK-384", PREFIX + "$Digest384");
				provider.addAlgorithm("MessageDigest.KECCAK-512", PREFIX + "$Digest512");

				addHMACAlgorithm(provider, "KECCAK224", PREFIX + "$HashMac224", PREFIX + "$KeyGenerator224");
				addHMACAlgorithm(provider, "KECCAK256", PREFIX + "$HashMac256", PREFIX + "$KeyGenerator256");
				addHMACAlgorithm(provider, "KECCAK288", PREFIX + "$HashMac288", PREFIX + "$KeyGenerator288");
				addHMACAlgorithm(provider, "KECCAK384", PREFIX + "$HashMac384", PREFIX + "$KeyGenerator384");
				addHMACAlgorithm(provider, "KECCAK512", PREFIX + "$HashMac512", PREFIX + "$KeyGenerator512");
			}
		}
	}

}