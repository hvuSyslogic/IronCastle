using org.bouncycastle.asn1.misc;

namespace org.bouncycastle.jcajce.provider.digest
{
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using Blake2sDigest = org.bouncycastle.crypto.digests.Blake2sDigest;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

	public class Blake2s
	{
		private Blake2s()
		{

		}

		public class Blake2s256 : BCMessageDigest, Cloneable
		{
			public Blake2s256() : base(new Blake2sDigest(256))
			{
			}

			public virtual object clone()
			{
				Blake2s256 d = (Blake2s256)base.clone();
				d.digest = new Blake2sDigest((Blake2sDigest)digest);

				return d;
			}
		}

		public class Blake2s224 : BCMessageDigest, Cloneable
		{
			public Blake2s224() : base(new Blake2sDigest(224))
			{
			}

			public virtual object clone()
			{
				Blake2s224 d = (Blake2s224)base.clone();
				d.digest = new Blake2sDigest((Blake2sDigest)digest);

				return d;
			}
		}

		public class Blake2s160 : BCMessageDigest, Cloneable
		{
			public Blake2s160() : base(new Blake2sDigest(160))
			{
			}

			public virtual object clone()
			{
				Blake2s160 d = (Blake2s160)base.clone();
				d.digest = new Blake2sDigest((Blake2sDigest)digest);

				return d;
			}
		}

		public class Blake2s128 : BCMessageDigest, Cloneable
		{
			public Blake2s128() : base(new Blake2sDigest(128))
			{
			}

			public virtual object clone()
			{
				Blake2s128 d = (Blake2s128)base.clone();
				d.digest = new Blake2sDigest((Blake2sDigest)digest);

				return d;
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Blake2s).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.BLAKE2S-256", PREFIX + "$Blake2s256");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers_Fields.id_blake2s256, "BLAKE2S-256");

				provider.addAlgorithm("MessageDigest.BLAKE2S-224", PREFIX + "$Blake2s224");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers_Fields.id_blake2s224, "BLAKE2S-224");

				provider.addAlgorithm("MessageDigest.BLAKE2S-160", PREFIX + "$Blake2s160");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers_Fields.id_blake2s160, "BLAKE2S-160");

				provider.addAlgorithm("MessageDigest.BLAKE2S-128", PREFIX + "$Blake2s128");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers_Fields.id_blake2s128, "BLAKE2S-128");
			}
		}
	}

}