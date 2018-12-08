using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jcajce.provider.digest
{
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using SHA224Digest = org.bouncycastle.crypto.digests.SHA224Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class SHA224
	{
		private SHA224()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new SHA224Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new SHA224Digest((SHA224Digest)digest);

				return d;
			}
		}

		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new SHA224Digest()))
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACSHA224", 224, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(SHA224).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.SHA-224", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest.SHA224", "SHA-224");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + NISTObjectIdentifiers_Fields.id_sha224, "SHA-224");

				provider.addAlgorithm("Mac.PBEWITHHMACSHA224", PREFIX + "$HashMac");

				addHMACAlgorithm(provider, "SHA224", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
				addHMACAlias(provider, "SHA224", PKCSObjectIdentifiers_Fields.id_hmacWithSHA224);

			}
		}
	}

}