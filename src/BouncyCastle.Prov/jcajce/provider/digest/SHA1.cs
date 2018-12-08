using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.iana;

namespace org.bouncycastle.jcajce.provider.digest
{
	using IANAObjectIdentifiers = org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using PBESecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;

	public class SHA1
	{
		private SHA1()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new SHA1Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new SHA1Digest((SHA1Digest)digest);

				return d;
			}
		}

		/// <summary>
		/// SHA1 HMac
		/// </summary>
		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new SHA1Digest()))
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACSHA1", 160, new CipherKeyGenerator())
			{
			}
		}

		/// <summary>
		/// SHA1 HMac
		/// </summary>
		public class SHA1Mac : BaseMac
		{
			public SHA1Mac() : base(new HMac(new SHA1Digest()))
			{
			}
		}

		/// <summary>
		/// PBEWithHmacSHA
		/// </summary>
		public class PBEWithMacKeyFactory : PBESecretKeyFactory
		{
			public PBEWithMacKeyFactory() : base("PBEwithHmacSHA", null, false, PKCS12, SHA1, 160, 0)
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(SHA1).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.SHA-1", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest.SHA1", "SHA-1");
				provider.addAlgorithm("Alg.Alias.MessageDigest.SHA", "SHA-1");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + OIWObjectIdentifiers_Fields.idSHA1, "SHA-1");

				addHMACAlgorithm(provider, "SHA1", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
				addHMACAlias(provider, "SHA1", PKCSObjectIdentifiers_Fields.id_hmacWithSHA1);
				addHMACAlias(provider, "SHA1", IANAObjectIdentifiers_Fields.hmacSHA1);

				provider.addAlgorithm("Mac.PBEWITHHMACSHA", PREFIX + "$SHA1Mac");
				provider.addAlgorithm("Mac.PBEWITHHMACSHA1", PREFIX + "$SHA1Mac");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHHMACSHA", "PBEWITHHMACSHA1");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory." + OIWObjectIdentifiers_Fields.idSHA1, "PBEWITHHMACSHA1");
				provider.addAlgorithm("Alg.Alias.Mac." + OIWObjectIdentifiers_Fields.idSHA1, "PBEWITHHMACSHA");

				provider.addAlgorithm("SecretKeyFactory.PBEWITHHMACSHA1", PREFIX + "$PBEWithMacKeyFactory");
			}
		}
	}

}