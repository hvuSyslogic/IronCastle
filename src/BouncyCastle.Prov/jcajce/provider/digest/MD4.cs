using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jcajce.provider.digest
{
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using MD4Digest = org.bouncycastle.crypto.digests.MD4Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class MD4
	{
		private MD4()
		{

		}

		/// <summary>
		/// MD4 HashMac
		/// </summary>
		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new MD4Digest()))
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACMD4", 128, new CipherKeyGenerator())
			{
			}
		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new MD4Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new MD4Digest((MD4Digest)digest);

				return d;
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(MD4).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.MD4", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + PKCSObjectIdentifiers_Fields.md4, "MD4");

				addHMACAlgorithm(provider, "MD4", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
			}
		}
	}

}