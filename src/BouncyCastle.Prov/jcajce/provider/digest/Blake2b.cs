using org.bouncycastle.asn1.misc;

namespace org.bouncycastle.jcajce.provider.digest
{
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using Blake2bDigest = org.bouncycastle.crypto.digests.Blake2bDigest;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

	public class Blake2b
	{
		private Blake2b()
		{

		}

		public class Blake2b512 : BCMessageDigest, Cloneable
		{
			public Blake2b512() : base(new Blake2bDigest(512))
			{
			}

			public virtual object clone()
			{
				Blake2b512 d = (Blake2b512)base.clone();
				d.digest = new Blake2bDigest((Blake2bDigest)digest);

				return d;
			}
		}

		public class Blake2b384 : BCMessageDigest, Cloneable
		{
			public Blake2b384() : base(new Blake2bDigest(384))
			{
			}

			public virtual object clone()
			{
				Blake2b384 d = (Blake2b384)base.clone();
				d.digest = new Blake2bDigest((Blake2bDigest)digest);

				return d;
			}
		}

		public class Blake2b256 : BCMessageDigest, Cloneable
		{
			public Blake2b256() : base(new Blake2bDigest(256))
			{
			}

			public virtual object clone()
			{
				Blake2b256 d = (Blake2b256)base.clone();
				d.digest = new Blake2bDigest((Blake2bDigest)digest);

				return d;
			}
		}

		public class Blake2b160 : BCMessageDigest, Cloneable
		{
			public Blake2b160() : base(new Blake2bDigest(160))
			{
			}

			public virtual object clone()
			{
				Blake2b160 d = (Blake2b160)base.clone();
				d.digest = new Blake2bDigest((Blake2bDigest)digest);

				return d;
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Blake2b).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.BLAKE2B-512", PREFIX + "$Blake2b512");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers_Fields.id_blake2b512, "BLAKE2B-512");

				provider.addAlgorithm("MessageDigest.BLAKE2B-384", PREFIX + "$Blake2b384");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers_Fields.id_blake2b384, "BLAKE2B-384");

				provider.addAlgorithm("MessageDigest.BLAKE2B-256", PREFIX + "$Blake2b256");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers_Fields.id_blake2b256, "BLAKE2B-256");

				provider.addAlgorithm("MessageDigest.BLAKE2B-160", PREFIX + "$Blake2b160");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers_Fields.id_blake2b160, "BLAKE2B-160");
			}
		}
	}

}