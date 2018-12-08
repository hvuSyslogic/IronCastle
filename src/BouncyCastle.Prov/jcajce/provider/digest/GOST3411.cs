using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;

namespace org.bouncycastle.jcajce.provider.digest
{
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using GOST3411Digest = org.bouncycastle.crypto.digests.GOST3411Digest;
	using GOST3411_2012_256Digest = org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
	using GOST3411_2012_512Digest = org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using PBESecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;

	public class GOST3411
	{
		private GOST3411()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new GOST3411Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new GOST3411Digest((GOST3411Digest)digest);

				return d;
			}
		}

		public class Digest2012_256 : BCMessageDigest, Cloneable
		{
			public Digest2012_256() : base(new GOST3411_2012_256Digest())
			{
			}

			public virtual object clone()
			{
				Digest2012_256 d = (Digest2012_256)base.clone();
				d.digest = new GOST3411_2012_256Digest((GOST3411_2012_256Digest)digest);

				return d;
			}
		}

		public class Digest2012_512 : BCMessageDigest, Cloneable
		{
			public Digest2012_512() : base(new GOST3411_2012_512Digest())
			{
			}

			public virtual object clone()
			{
				Digest2012_512 d = (Digest2012_512)base.clone();
				d.digest = new GOST3411_2012_512Digest((GOST3411_2012_512Digest)digest);

				return d;
			}
		}

		/// <summary>
		/// GOST3411 HMac
		/// </summary>
		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new GOST3411Digest()))
			{
			}
		}

		public class HashMac2012_256 : BaseMac
		{
			public HashMac2012_256() : base(new HMac(new GOST3411_2012_256Digest()))
			{
			}
		}

		public class HashMac2012_512 : BaseMac
		{
			public HashMac2012_512() : base(new HMac(new GOST3411_2012_512Digest()))
			{
			}
		}

		/// <summary>
		/// PBEWithHmacGOST3411
		/// </summary>
		public class PBEWithMacKeyFactory : PBESecretKeyFactory
		{
			public PBEWithMacKeyFactory() : base("PBEwithHmacGOST3411", null, false, PKCS12, GOST3411, 256, 0)
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACGOST3411", 256, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGenerator2012_256 : BaseKeyGenerator
		{
			public KeyGenerator2012_256() : base("HMACGOST3411", 256, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGenerator2012_512 : BaseKeyGenerator
		{
			public KeyGenerator2012_512() : base("HMACGOST3411", 512, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(GOST3411).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.GOST3411", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest.GOST", "GOST3411");
				provider.addAlgorithm("Alg.Alias.MessageDigest.GOST-3411", "GOST3411");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + CryptoProObjectIdentifiers_Fields.gostR3411, "GOST3411");

				addHMACAlgorithm(provider, "GOST3411", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
				addHMACAlias(provider, "GOST3411", CryptoProObjectIdentifiers_Fields.gostR3411);

				provider.addAlgorithm("MessageDigest.GOST3411-2012-256", PREFIX + "$Digest2012_256");
				provider.addAlgorithm("Alg.Alias.MessageDigest.GOST-2012-256", "GOST3411-2012-256");
				provider.addAlgorithm("Alg.Alias.MessageDigest.GOST-3411-2012-256", "GOST3411-2012-256");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256, "GOST3411-2012-256");

				addHMACAlgorithm(provider, "GOST3411-2012-256", PREFIX + "$HashMac2012_256", PREFIX + "$KeyGenerator2012_256");
				addHMACAlias(provider, "GOST3411-2012-256", RosstandartObjectIdentifiers_Fields.id_tc26_hmac_gost_3411_12_256);

				provider.addAlgorithm("MessageDigest.GOST3411-2012-512", PREFIX + "$Digest2012_512");
				provider.addAlgorithm("Alg.Alias.MessageDigest.GOST-2012-512", "GOST3411-2012-512");
				provider.addAlgorithm("Alg.Alias.MessageDigest.GOST-3411-2012-512", "GOST3411-2012-512");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512, "GOST3411-2012-512");

				addHMACAlgorithm(provider, "GOST3411-2012-512", PREFIX + "$HashMac2012_512", PREFIX + "$KeyGenerator2012_512");
				addHMACAlias(provider, "GOST3411-2012-512", RosstandartObjectIdentifiers_Fields.id_tc26_hmac_gost_3411_12_512);

				provider.addAlgorithm("SecretKeyFactory.PBEWITHHMACGOST3411", PREFIX + "$PBEWithMacKeyFactory");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory." + CryptoProObjectIdentifiers_Fields.gostR3411, "PBEWITHHMACGOST3411");
			}
		}
	}

}