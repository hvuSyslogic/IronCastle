using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jcajce.provider.digest
{
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using SHA512tDigest = org.bouncycastle.crypto.digests.SHA512tDigest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using OldHMac = org.bouncycastle.crypto.macs.OldHMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class SHA512
	{
		private SHA512()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new SHA512Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new SHA512Digest((SHA512Digest)digest);

				return d;
			}
		}

		public class DigestT : BCMessageDigest, Cloneable
		{
			public DigestT(int bitLength) : base(new SHA512tDigest(bitLength))
			{
			}

			public virtual object clone()
			{
				DigestT d = (DigestT)base.clone();
				d.digest = new SHA512tDigest((SHA512tDigest)digest);

				return d;
			}
		}

		public class DigestT224 : DigestT
		{
			public DigestT224() : base(224)
			{
			}
		}

		public class DigestT256 : DigestT
		{
			public DigestT256() : base(256)
			{
			}
		}

		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new SHA512Digest()))
			{
			}
		}

		public class HashMacT224 : BaseMac
		{
			public HashMacT224() : base(new HMac(new SHA512tDigest(224)))
			{
			}
		}

		public class HashMacT256 : BaseMac
		{
			public HashMacT256() : base(new HMac(new SHA512tDigest(256)))
			{
			}
		}

		/// <summary>
		/// SHA-512 HMac
		/// </summary>
		public class OldSHA512 : BaseMac
		{
			public OldSHA512() : base(new OldHMac(new SHA512Digest()))
			{
			}
		}

		/// <summary>
		/// HMACSHA512
		/// </summary>
		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACSHA512", 512, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGeneratorT224 : BaseKeyGenerator
		{
			public KeyGeneratorT224() : base("HMACSHA512/224", 224, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGeneratorT256 : BaseKeyGenerator
		{
			public KeyGeneratorT256() : base("HMACSHA512/256", 256, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(SHA512).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.SHA-512", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest.SHA512", "SHA-512");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + NISTObjectIdentifiers_Fields.id_sha512, "SHA-512");

				provider.addAlgorithm("MessageDigest.SHA-512/224", PREFIX + "$DigestT224");
				provider.addAlgorithm("Alg.Alias.MessageDigest.SHA512/224", "SHA-512/224");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + NISTObjectIdentifiers_Fields.id_sha512_224, "SHA-512/224");

				provider.addAlgorithm("MessageDigest.SHA-512/256", PREFIX + "$DigestT256");
				provider.addAlgorithm("Alg.Alias.MessageDigest.SHA512256", "SHA-512/256");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + NISTObjectIdentifiers_Fields.id_sha512_256, "SHA-512/256");

				provider.addAlgorithm("Mac.OLDHMACSHA512", PREFIX + "$OldSHA512");

				provider.addAlgorithm("Mac.PBEWITHHMACSHA512", PREFIX + "$HashMac");

				addHMACAlgorithm(provider, "SHA512", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
				addHMACAlias(provider, "SHA512", PKCSObjectIdentifiers_Fields.id_hmacWithSHA512);

				addHMACAlgorithm(provider, "SHA512/224", PREFIX + "$HashMacT224", PREFIX + "$KeyGeneratorT224");
				addHMACAlgorithm(provider, "SHA512/256", PREFIX + "$HashMacT256", PREFIX + "$KeyGeneratorT256");
			}
		}

	}

}