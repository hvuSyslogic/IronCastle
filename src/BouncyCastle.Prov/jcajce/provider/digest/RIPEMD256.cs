using org.bouncycastle.asn1.teletrust;

namespace org.bouncycastle.jcajce.provider.digest
{
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using RIPEMD256Digest = org.bouncycastle.crypto.digests.RIPEMD256Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class RIPEMD256
	{
		private RIPEMD256()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new RIPEMD256Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new RIPEMD256Digest((RIPEMD256Digest)digest);

				return d;
			}
		}

		/// <summary>
		/// RIPEMD256 HMac
		/// </summary>
		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new RIPEMD256Digest()))
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACRIPEMD256", 256, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(RIPEMD256).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.RIPEMD256", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + TeleTrusTObjectIdentifiers_Fields.ripemd256, "RIPEMD256");

				addHMACAlgorithm(provider, "RIPEMD256", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
			}
		}
	}

}