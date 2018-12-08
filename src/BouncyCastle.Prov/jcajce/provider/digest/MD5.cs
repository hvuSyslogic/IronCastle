using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.iana;

namespace org.bouncycastle.jcajce.provider.digest
{
	using IANAObjectIdentifiers = org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using MD5Digest = org.bouncycastle.crypto.digests.MD5Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class MD5
	{
		private MD5()
		{

		}

		/// <summary>
		/// MD5 HashMac
		/// </summary>
		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new MD5Digest()))
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACMD5", 128, new CipherKeyGenerator())
			{
			}
		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new MD5Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new MD5Digest((MD5Digest)digest);

				return d;
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(MD5).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.MD5", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + PKCSObjectIdentifiers_Fields.md5, "MD5");

				addHMACAlgorithm(provider, "MD5", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
				addHMACAlias(provider, "MD5", IANAObjectIdentifiers_Fields.hmacMD5);
			}
		}
	}

}