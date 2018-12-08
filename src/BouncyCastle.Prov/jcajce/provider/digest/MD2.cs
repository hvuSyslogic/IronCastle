using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jcajce.provider.digest
{
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using MD2Digest = org.bouncycastle.crypto.digests.MD2Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class MD2
	{
		private MD2()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new MD2Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new MD2Digest((MD2Digest)digest);

				return d;
			}
		}

		/// <summary>
		/// MD2 HMac
		/// </summary>
		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new MD2Digest()))
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACMD2", 128, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(MD2).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.MD2", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + PKCSObjectIdentifiers_Fields.md2, "MD2");

				addHMACAlgorithm(provider, "MD2", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
			}
		}
	}

}