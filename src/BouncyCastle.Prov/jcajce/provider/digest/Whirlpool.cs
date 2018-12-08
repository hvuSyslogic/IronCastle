using org.bouncycastle.asn1.iso;

namespace org.bouncycastle.jcajce.provider.digest
{
	using ISOIECObjectIdentifiers = org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using WhirlpoolDigest = org.bouncycastle.crypto.digests.WhirlpoolDigest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class Whirlpool
	{
		private Whirlpool()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new WhirlpoolDigest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new WhirlpoolDigest((WhirlpoolDigest)digest);

				return d;
			}
		}

		/// <summary>
		/// Tiger HMac
		/// </summary>
		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new WhirlpoolDigest()))
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACWHIRLPOOL", 512, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Whirlpool).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.WHIRLPOOL", PREFIX + "$Digest");
				provider.addAlgorithm("MessageDigest", ISOIECObjectIdentifiers_Fields.whirlpool, PREFIX + "$Digest");

				addHMACAlgorithm(provider, "WHIRLPOOL", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
			}
		}
	}

}