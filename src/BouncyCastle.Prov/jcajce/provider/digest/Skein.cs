namespace org.bouncycastle.jcajce.provider.digest
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using SkeinDigest = org.bouncycastle.crypto.digests.SkeinDigest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using SkeinMac = org.bouncycastle.crypto.macs.SkeinMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class Skein
	{
		private Skein()
		{
		}

		public class DigestSkein256 : BCMessageDigest, Cloneable
		{
			public DigestSkein256(int outputSize) : base(new SkeinDigest(SkeinDigest.SKEIN_256, outputSize))
			{
			}

			public virtual object clone()
			{
				BCMessageDigest d = (BCMessageDigest)base.clone();
				d.digest = new SkeinDigest((SkeinDigest)digest);

				return d;
			}
		}

		public class Digest_256_128 : DigestSkein256
		{
			public Digest_256_128() : base(128)
			{
			}
		}

		public class Digest_256_160 : DigestSkein256
		{
			public Digest_256_160() : base(160)
			{
			}
		}

		public class Digest_256_224 : DigestSkein256
		{
			public Digest_256_224() : base(224)
			{
			}
		}

		public class Digest_256_256 : DigestSkein256
		{
			public Digest_256_256() : base(256)
			{
			}
		}

		public class DigestSkein512 : BCMessageDigest, Cloneable
		{
			public DigestSkein512(int outputSize) : base(new SkeinDigest(SkeinDigest.SKEIN_512, outputSize))
			{
			}

			public virtual object clone()
			{
				BCMessageDigest d = (BCMessageDigest)base.clone();
				d.digest = new SkeinDigest((SkeinDigest)digest);

				return d;
			}
		}

		public class Digest_512_128 : DigestSkein512
		{
			public Digest_512_128() : base(128)
			{
			}
		}

		public class Digest_512_160 : DigestSkein512
		{
			public Digest_512_160() : base(160)
			{
			}
		}

		public class Digest_512_224 : DigestSkein512
		{
			public Digest_512_224() : base(224)
			{
			}
		}

		public class Digest_512_256 : DigestSkein512
		{
			public Digest_512_256() : base(256)
			{
			}
		}

		public class Digest_512_384 : DigestSkein512
		{
			public Digest_512_384() : base(384)
			{
			}
		}

		public class Digest_512_512 : DigestSkein512
		{
			public Digest_512_512() : base(512)
			{
			}
		}

		public class DigestSkein1024 : BCMessageDigest, Cloneable
		{
			public DigestSkein1024(int outputSize) : base(new SkeinDigest(SkeinDigest.SKEIN_1024, outputSize))
			{
			}

			public virtual object clone()
			{
				BCMessageDigest d = (BCMessageDigest)base.clone();
				d.digest = new SkeinDigest((SkeinDigest)digest);

				return d;
			}
		}

		public class Digest_1024_384 : DigestSkein1024
		{
			public Digest_1024_384() : base(384)
			{
			}
		}

		public class Digest_1024_512 : DigestSkein1024
		{
			public Digest_1024_512() : base(512)
			{
			}
		}

		public class Digest_1024_1024 : DigestSkein1024
		{
			public Digest_1024_1024() : base(1024)
			{
			}
		}

		/// <summary>
		/// Skein HMac
		/// </summary>
		public class HashMac_256_128 : BaseMac
		{
			public HashMac_256_128() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_256, 128)))
			{
			}
		}

		public class HashMac_256_160 : BaseMac
		{
			public HashMac_256_160() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_256, 160)))
			{
			}
		}

		public class HashMac_256_224 : BaseMac
		{
			public HashMac_256_224() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_256, 224)))
			{
			}
		}

		public class HashMac_256_256 : BaseMac
		{
			public HashMac_256_256() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_256, 256)))
			{
			}
		}

		public class HashMac_512_128 : BaseMac
		{
			public HashMac_512_128() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_512, 128)))
			{
			}
		}

		public class HashMac_512_160 : BaseMac
		{
			public HashMac_512_160() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_512, 160)))
			{
			}
		}

		public class HashMac_512_224 : BaseMac
		{
			public HashMac_512_224() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_512, 224)))
			{
			}
		}

		public class HashMac_512_256 : BaseMac
		{
			public HashMac_512_256() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_512, 256)))
			{
			}
		}

		public class HashMac_512_384 : BaseMac
		{
			public HashMac_512_384() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_512, 384)))
			{
			}
		}

		public class HashMac_512_512 : BaseMac
		{
			public HashMac_512_512() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_512, 512)))
			{
			}
		}

		public class HashMac_1024_384 : BaseMac
		{
			public HashMac_1024_384() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_1024, 384)))
			{
			}
		}

		public class HashMac_1024_512 : BaseMac
		{
			public HashMac_1024_512() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_1024, 512)))
			{
			}
		}

		public class HashMac_1024_1024 : BaseMac
		{
			public HashMac_1024_1024() : base(new HMac(new SkeinDigest(SkeinDigest.SKEIN_1024, 1024)))
			{
			}
		}

		public class HMacKeyGenerator_256_128 : BaseKeyGenerator
		{
			public HMacKeyGenerator_256_128() : base("HMACSkein-256-128", 128, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_256_160 : BaseKeyGenerator
		{
			public HMacKeyGenerator_256_160() : base("HMACSkein-256-160", 160, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_256_224 : BaseKeyGenerator
		{
			public HMacKeyGenerator_256_224() : base("HMACSkein-256-224", 224, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_256_256 : BaseKeyGenerator
		{
			public HMacKeyGenerator_256_256() : base("HMACSkein-256-256", 256, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_512_128 : BaseKeyGenerator
		{
			public HMacKeyGenerator_512_128() : base("HMACSkein-512-128", 128, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_512_160 : BaseKeyGenerator
		{
			public HMacKeyGenerator_512_160() : base("HMACSkein-512-160", 160, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_512_224 : BaseKeyGenerator
		{
			public HMacKeyGenerator_512_224() : base("HMACSkein-512-224", 224, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_512_256 : BaseKeyGenerator
		{
			public HMacKeyGenerator_512_256() : base("HMACSkein-512-256", 256, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_512_384 : BaseKeyGenerator
		{
			public HMacKeyGenerator_512_384() : base("HMACSkein-512-384", 384, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_512_512 : BaseKeyGenerator
		{
			public HMacKeyGenerator_512_512() : base("HMACSkein-512-512", 512, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_1024_384 : BaseKeyGenerator
		{
			public HMacKeyGenerator_1024_384() : base("HMACSkein-1024-384", 384, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_1024_512 : BaseKeyGenerator
		{
			public HMacKeyGenerator_1024_512() : base("HMACSkein-1024-512", 512, new CipherKeyGenerator())
			{
			}
		}

		public class HMacKeyGenerator_1024_1024 : BaseKeyGenerator
		{
			public HMacKeyGenerator_1024_1024() : base("HMACSkein-1024-1024", 1024, new CipherKeyGenerator())
			{
			}
		}

		/*
		 * Skein-MAC
		 */
		public class SkeinMac_256_128 : BaseMac
		{
			public SkeinMac_256_128() : base(new SkeinMac(SkeinMac.SKEIN_256, 128))
			{
			}
		}

		public class SkeinMac_256_160 : BaseMac
		{
			public SkeinMac_256_160() : base(new SkeinMac(SkeinMac.SKEIN_256, 160))
			{
			}
		}

		public class SkeinMac_256_224 : BaseMac
		{
			public SkeinMac_256_224() : base(new SkeinMac(SkeinMac.SKEIN_256, 224))
			{
			}
		}

		public class SkeinMac_256_256 : BaseMac
		{
			public SkeinMac_256_256() : base(new SkeinMac(SkeinMac.SKEIN_256, 256))
			{
			}
		}

		public class SkeinMac_512_128 : BaseMac
		{
			public SkeinMac_512_128() : base(new SkeinMac(SkeinMac.SKEIN_512, 128))
			{
			}
		}

		public class SkeinMac_512_160 : BaseMac
		{
			public SkeinMac_512_160() : base(new SkeinMac(SkeinMac.SKEIN_512, 160))
			{
			}
		}

		public class SkeinMac_512_224 : BaseMac
		{
			public SkeinMac_512_224() : base(new SkeinMac(SkeinMac.SKEIN_512, 224))
			{
			}
		}

		public class SkeinMac_512_256 : BaseMac
		{
			public SkeinMac_512_256() : base(new SkeinMac(SkeinMac.SKEIN_512, 256))
			{
			}
		}

		public class SkeinMac_512_384 : BaseMac
		{
			public SkeinMac_512_384() : base(new SkeinMac(SkeinMac.SKEIN_512, 384))
			{
			}
		}

		public class SkeinMac_512_512 : BaseMac
		{
			public SkeinMac_512_512() : base(new SkeinMac(SkeinMac.SKEIN_512, 512))
			{
			}
		}

		public class SkeinMac_1024_384 : BaseMac
		{
			public SkeinMac_1024_384() : base(new SkeinMac(SkeinMac.SKEIN_1024, 384))
			{
			}
		}

		public class SkeinMac_1024_512 : BaseMac
		{
			public SkeinMac_1024_512() : base(new SkeinMac(SkeinMac.SKEIN_1024, 512))
			{
			}
		}

		public class SkeinMac_1024_1024 : BaseMac
		{
			public SkeinMac_1024_1024() : base(new SkeinMac(SkeinMac.SKEIN_1024, 1024))
			{
			}
		}

		public class SkeinMacKeyGenerator_256_128 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_256_128() : base("Skein-MAC-256-128", 128, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_256_160 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_256_160() : base("Skein-MAC-256-160", 160, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_256_224 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_256_224() : base("Skein-MAC-256-224", 224, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_256_256 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_256_256() : base("Skein-MAC-256-256", 256, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_512_128 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_512_128() : base("Skein-MAC-512-128", 128, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_512_160 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_512_160() : base("Skein-MAC-512-160", 160, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_512_224 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_512_224() : base("Skein-MAC-512-224", 224, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_512_256 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_512_256() : base("Skein-MAC-512-256", 256, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_512_384 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_512_384() : base("Skein-MAC-512-384", 384, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_512_512 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_512_512() : base("Skein-MAC-512-512", 512, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_1024_384 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_1024_384() : base("Skein-MAC-1024-384", 384, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_1024_512 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_1024_512() : base("Skein-MAC-1024-512", 512, new CipherKeyGenerator())
			{
			}
		}

		public class SkeinMacKeyGenerator_1024_1024 : BaseKeyGenerator
		{
			public SkeinMacKeyGenerator_1024_1024() : base("Skein-MAC-1024-1024", 1024, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Skein).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				// Skein sizes as used in "The Skein Hash Function Family 1.3"

				provider.addAlgorithm("MessageDigest.Skein-256-128", PREFIX + "$Digest_256_128");
				provider.addAlgorithm("MessageDigest.Skein-256-160", PREFIX + "$Digest_256_160");
				provider.addAlgorithm("MessageDigest.Skein-256-224", PREFIX + "$Digest_256_224");
				provider.addAlgorithm("MessageDigest.Skein-256-256", PREFIX + "$Digest_256_256");

				provider.addAlgorithm("MessageDigest.Skein-512-128", PREFIX + "$Digest_512_128");
				provider.addAlgorithm("MessageDigest.Skein-512-160", PREFIX + "$Digest_512_160");
				provider.addAlgorithm("MessageDigest.Skein-512-224", PREFIX + "$Digest_512_224");
				provider.addAlgorithm("MessageDigest.Skein-512-256", PREFIX + "$Digest_512_256");
				provider.addAlgorithm("MessageDigest.Skein-512-384", PREFIX + "$Digest_512_384");
				provider.addAlgorithm("MessageDigest.Skein-512-512", PREFIX + "$Digest_512_512");

				provider.addAlgorithm("MessageDigest.Skein-1024-384", PREFIX + "$Digest_1024_384");
				provider.addAlgorithm("MessageDigest.Skein-1024-512", PREFIX + "$Digest_1024_512");
				provider.addAlgorithm("MessageDigest.Skein-1024-1024", PREFIX + "$Digest_1024_1024");

				addHMACAlgorithm(provider, "Skein-256-128", PREFIX + "$HashMac_256_128", PREFIX + "$HMacKeyGenerator_256_128");
				addHMACAlgorithm(provider, "Skein-256-160", PREFIX + "$HashMac_256_160", PREFIX + "$HMacKeyGenerator_256_160");
				addHMACAlgorithm(provider, "Skein-256-224", PREFIX + "$HashMac_256_224", PREFIX + "$HMacKeyGenerator_256_224");
				addHMACAlgorithm(provider, "Skein-256-256", PREFIX + "$HashMac_256_256", PREFIX + "$HMacKeyGenerator_256_256");

				addHMACAlgorithm(provider, "Skein-512-128", PREFIX + "$HashMac_512_128", PREFIX + "$HMacKeyGenerator_512_128");
				addHMACAlgorithm(provider, "Skein-512-160", PREFIX + "$HashMac_512_160", PREFIX + "$HMacKeyGenerator_512_160");
				addHMACAlgorithm(provider, "Skein-512-224", PREFIX + "$HashMac_512_224", PREFIX + "$HMacKeyGenerator_512_224");
				addHMACAlgorithm(provider, "Skein-512-256", PREFIX + "$HashMac_512_256", PREFIX + "$HMacKeyGenerator_512_256");
				addHMACAlgorithm(provider, "Skein-512-384", PREFIX + "$HashMac_512_384", PREFIX + "$HMacKeyGenerator_512_384");
				addHMACAlgorithm(provider, "Skein-512-512", PREFIX + "$HashMac_512_512", PREFIX + "$HMacKeyGenerator_512_512");

				addHMACAlgorithm(provider, "Skein-1024-384", PREFIX + "$HashMac_1024_384", PREFIX + "$HMacKeyGenerator_1024_384");
				addHMACAlgorithm(provider, "Skein-1024-512", PREFIX + "$HashMac_1024_512", PREFIX + "$HMacKeyGenerator_1024_512");
				addHMACAlgorithm(provider, "Skein-1024-1024", PREFIX + "$HashMac_1024_1024", PREFIX + "$HMacKeyGenerator_1024_1024");

				addSkeinMacAlgorithm(provider, 256, 128);
				addSkeinMacAlgorithm(provider, 256, 160);
				addSkeinMacAlgorithm(provider, 256, 224);
				addSkeinMacAlgorithm(provider, 256, 256);

				addSkeinMacAlgorithm(provider, 512, 128);
				addSkeinMacAlgorithm(provider, 512, 160);
				addSkeinMacAlgorithm(provider, 512, 224);
				addSkeinMacAlgorithm(provider, 512, 256);
				addSkeinMacAlgorithm(provider, 512, 384);
				addSkeinMacAlgorithm(provider, 512, 512);

				addSkeinMacAlgorithm(provider, 1024, 384);
				addSkeinMacAlgorithm(provider, 1024, 512);
				addSkeinMacAlgorithm(provider, 1024, 1024);
			}

			public virtual void addSkeinMacAlgorithm(ConfigurableProvider provider, int blockSize, int outputSize)
			{
				string mainName = "Skein-MAC-" + blockSize + "-" + outputSize;
				string algorithmClassName = PREFIX + "$SkeinMac_" + blockSize + "_" + outputSize;
				string keyGeneratorClassName = PREFIX + "$SkeinMacKeyGenerator_" + blockSize + "_" + outputSize;

				provider.addAlgorithm("Mac." + mainName, algorithmClassName);
				provider.addAlgorithm("Alg.Alias.Mac.Skein-MAC" + blockSize + "/" + outputSize, mainName);
				provider.addAlgorithm("KeyGenerator." + mainName, keyGeneratorClassName);
				provider.addAlgorithm("Alg.Alias.KeyGenerator.Skein-MAC" + blockSize + "/" + outputSize, mainName);
			}

		}
	}

}