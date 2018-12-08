using org.bouncycastle.asn1.nist;

namespace org.bouncycastle.jcajce.provider.digest
{
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using SHA3Digest = org.bouncycastle.crypto.digests.SHA3Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class SHA3
	{
		private SHA3()
		{

		}

		public class DigestSHA3 : BCMessageDigest, Cloneable
		{
			public DigestSHA3(int size) : base(new SHA3Digest(size))
			{
			}

			public virtual object clone()
			{
				BCMessageDigest d = (BCMessageDigest)base.clone();
				d.digest = new SHA3Digest((SHA3Digest)digest);

				return d;
			}
		}

		public class HashMacSHA3 : BaseMac
		{
			public HashMacSHA3(int size) : base(new HMac(new SHA3Digest(size)))
			{
			}
		}

		public class KeyGeneratorSHA3 : BaseKeyGenerator
		{
			public KeyGeneratorSHA3(int size) : base("HMACSHA3-" + size, size, new CipherKeyGenerator())
			{
			}
		}

		public class Digest224 : DigestSHA3
		{
			public Digest224() : base(224)
			{
			}
		}

		public class Digest256 : DigestSHA3
		{
			public Digest256() : base(256)
			{
			}
		}

		public class Digest384 : DigestSHA3
		{
			public Digest384() : base(384)
			{
			}
		}

		public class Digest512 : DigestSHA3
		{
			public Digest512() : base(512)
			{
			}
		}

		public class HashMac224 : HashMacSHA3
		{
			public HashMac224() : base(224)
			{
			}
		}

		public class HashMac256 : HashMacSHA3
		{
			public HashMac256() : base(256)
			{
			}
		}

		public class HashMac384 : HashMacSHA3
		{
			public HashMac384() : base(384)
			{
			}
		}

		public class HashMac512 : HashMacSHA3
		{
			public HashMac512() : base(512)
			{
			}
		}

		public class KeyGenerator224 : KeyGeneratorSHA3
		{
			public KeyGenerator224() : base(224)
			{
			}
		}

		public class KeyGenerator256 : KeyGeneratorSHA3
		{
			public KeyGenerator256() : base(256)
			{
			}
		}

		public class KeyGenerator384 : KeyGeneratorSHA3
		{
			public KeyGenerator384() : base(384)
			{
			}
		}

		public class KeyGenerator512 : KeyGeneratorSHA3
		{
			public KeyGenerator512() : base(512)
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(SHA3).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.SHA3-224", PREFIX + "$Digest224");
				provider.addAlgorithm("MessageDigest.SHA3-256", PREFIX + "$Digest256");
				provider.addAlgorithm("MessageDigest.SHA3-384", PREFIX + "$Digest384");
				provider.addAlgorithm("MessageDigest.SHA3-512", PREFIX + "$Digest512");
				provider.addAlgorithm("MessageDigest", NISTObjectIdentifiers_Fields.id_sha3_224, PREFIX + "$Digest224");
				provider.addAlgorithm("MessageDigest", NISTObjectIdentifiers_Fields.id_sha3_256, PREFIX + "$Digest256");
				provider.addAlgorithm("MessageDigest", NISTObjectIdentifiers_Fields.id_sha3_384, PREFIX + "$Digest384");
				provider.addAlgorithm("MessageDigest", NISTObjectIdentifiers_Fields.id_sha3_512, PREFIX + "$Digest512");

				addHMACAlgorithm(provider, "SHA3-224", PREFIX + "$HashMac224", PREFIX + "$KeyGenerator224");
				addHMACAlias(provider, "SHA3-224", NISTObjectIdentifiers_Fields.id_hmacWithSHA3_224);

				addHMACAlgorithm(provider, "SHA3-256", PREFIX + "$HashMac256", PREFIX + "$KeyGenerator256");
				addHMACAlias(provider, "SHA3-256", NISTObjectIdentifiers_Fields.id_hmacWithSHA3_256);

				addHMACAlgorithm(provider, "SHA3-384", PREFIX + "$HashMac384", PREFIX + "$KeyGenerator384");
				addHMACAlias(provider, "SHA3-384", NISTObjectIdentifiers_Fields.id_hmacWithSHA3_384);

				addHMACAlgorithm(provider, "SHA3-512", PREFIX + "$HashMac512", PREFIX + "$KeyGenerator512");
				addHMACAlias(provider, "SHA3-512", NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512);
			}
		}
	}

}