using org.bouncycastle.asn1.ua;

namespace org.bouncycastle.jcajce.provider.digest
{
	using UAObjectIdentifiers = org.bouncycastle.asn1.ua.UAObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using DSTU7564Digest = org.bouncycastle.crypto.digests.DSTU7564Digest;
	using DSTU7564Mac = org.bouncycastle.crypto.macs.DSTU7564Mac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class DSTU7564
	{
		private DSTU7564()
		{

		}

		public class DigestDSTU7564 : BCMessageDigest, Cloneable
		{
			public DigestDSTU7564(int size) : base(new DSTU7564Digest(size))
			{
			}

			public virtual object clone()
			{
				BCMessageDigest d = (BCMessageDigest)base.clone();
				d.digest = new DSTU7564Digest((DSTU7564Digest)digest);

				return d;
			}
		}

		public class Digest256 : DigestDSTU7564
		{
			public Digest256() : base(256)
			{
			}
		}

		public class Digest384 : DigestDSTU7564
		{
			public Digest384() : base(384)
			{
			}
		}

		public class Digest512 : DigestDSTU7564
		{
			public Digest512() : base(512)
			{
			}
		}

		public class HashMac256 : BaseMac
		{
			public HashMac256() : base(new DSTU7564Mac(256))
			{
			}
		}

		public class HashMac384 : BaseMac
		{
			public HashMac384() : base(new DSTU7564Mac(384))
			{
			}
		}

		public class HashMac512 : BaseMac
		{
			public HashMac512() : base(new DSTU7564Mac(512))
			{
			}
		}

		public class KeyGenerator256 : BaseKeyGenerator
		{
			public KeyGenerator256() : base("HMACDSTU7564-256", 256, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGenerator384 : BaseKeyGenerator
		{
			public KeyGenerator384() : base("HMACDSTU7564-384", 384, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGenerator512 : BaseKeyGenerator
		{
			public KeyGenerator512() : base("HMACDSTU7564-512", 512, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(DSTU7564).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.DSTU7564-256", PREFIX + "$Digest256");
				provider.addAlgorithm("MessageDigest.DSTU7564-384", PREFIX + "$Digest384");
				provider.addAlgorithm("MessageDigest.DSTU7564-512", PREFIX + "$Digest512");

				provider.addAlgorithm("MessageDigest", UAObjectIdentifiers_Fields.dstu7564digest_256, PREFIX + "$Digest256");
				provider.addAlgorithm("MessageDigest", UAObjectIdentifiers_Fields.dstu7564digest_384, PREFIX + "$Digest384");
				provider.addAlgorithm("MessageDigest", UAObjectIdentifiers_Fields.dstu7564digest_512, PREFIX + "$Digest512");

				addHMACAlgorithm(provider, "DSTU7564-256", PREFIX + "$HashMac256", PREFIX + "$KeyGenerator256");
				addHMACAlgorithm(provider, "DSTU7564-384", PREFIX + "$HashMac384", PREFIX + "$KeyGenerator384");
				addHMACAlgorithm(provider, "DSTU7564-512", PREFIX + "$HashMac512", PREFIX + "$KeyGenerator512");

				addHMACAlias(provider, "DSTU7564-256", UAObjectIdentifiers_Fields.dstu7564mac_256);
				addHMACAlias(provider, "DSTU7564-384", UAObjectIdentifiers_Fields.dstu7564mac_384);
				addHMACAlias(provider, "DSTU7564-512", UAObjectIdentifiers_Fields.dstu7564mac_512);
			}
		}
	}

}