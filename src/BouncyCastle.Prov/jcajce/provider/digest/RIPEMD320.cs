namespace org.bouncycastle.jcajce.provider.digest
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using RIPEMD320Digest = org.bouncycastle.crypto.digests.RIPEMD320Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class RIPEMD320
	{
		private RIPEMD320()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new RIPEMD320Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new RIPEMD320Digest((RIPEMD320Digest)digest);

				return d;
			}
		}

		/// <summary>
		/// RIPEMD320 HMac
		/// </summary>
		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new RIPEMD320Digest()))
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACRIPEMD320", 320, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(RIPEMD320).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.RIPEMD320", PREFIX + "$Digest");

				addHMACAlgorithm(provider, "RIPEMD320", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
			}
		}
	}

}