using org.bouncycastle.asn1.teletrust;

namespace org.bouncycastle.jcajce.provider.digest
{
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using RIPEMD128Digest = org.bouncycastle.crypto.digests.RIPEMD128Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class RIPEMD128
	{
		private RIPEMD128()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new RIPEMD128Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new RIPEMD128Digest((RIPEMD128Digest)digest);

				return d;
			}
		}

		/// <summary>
		/// RIPEMD128 HashMac
		/// </summary>
		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new RIPEMD128Digest()))
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACRIPEMD128", 128, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(RIPEMD128).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.RIPEMD128", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + TeleTrusTObjectIdentifiers_Fields.ripemd128, "RIPEMD128");

				addHMACAlgorithm(provider, "RIPEMD128", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
			}
		}
	}

}