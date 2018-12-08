using org.bouncycastle.asn1.iana;

namespace org.bouncycastle.jcajce.provider.digest
{
	using IANAObjectIdentifiers = org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using TigerDigest = org.bouncycastle.crypto.digests.TigerDigest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using PBESecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;

	public class Tiger
	{
		private Tiger()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new TigerDigest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new TigerDigest((TigerDigest)digest);

				return d;
			}
		}

		/// <summary>
		/// Tiger HMac
		/// </summary>
		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new TigerDigest()))
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACTIGER", 192, new CipherKeyGenerator())
			{
			}
		}

		/// <summary>
		/// Tiger HMac
		/// </summary>
		public class TigerHmac : BaseMac
		{
			public TigerHmac() : base(new HMac(new TigerDigest()))
			{
			}
		}

		/// <summary>
		/// PBEWithHmacTiger
		/// </summary>
		public class PBEWithMacKeyFactory : PBESecretKeyFactory
		{
			public PBEWithMacKeyFactory() : base("PBEwithHmacTiger", null, false, PKCS12, TIGER, 192, 0)
			{
			}
		}

		/// <summary>
		/// PBEWithHmacTiger
		/// </summary>
		public class PBEWithHashMac : BaseMac
		{
			public PBEWithHashMac() : base(new HMac(new TigerDigest()), PKCS12, TIGER, 192)
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Tiger).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.TIGER", PREFIX + "$Digest");
				provider.addAlgorithm("MessageDigest.Tiger", PREFIX + "$Digest"); // JDK 1.1.

				addHMACAlgorithm(provider, "TIGER", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
				addHMACAlias(provider, "TIGER", IANAObjectIdentifiers_Fields.hmacTIGER);

				provider.addAlgorithm("SecretKeyFactory.PBEWITHHMACTIGER", PREFIX + "$PBEWithMacKeyFactory");
			}
		}
	}

}