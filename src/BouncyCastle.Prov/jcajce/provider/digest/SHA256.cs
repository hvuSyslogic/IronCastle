using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jcajce.provider.digest
{
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using PBESecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;

	public class SHA256
	{
		private SHA256()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new SHA256Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new SHA256Digest((SHA256Digest)digest);

				return d;
			}
		}

		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new SHA256Digest()))
			{
			}
		}

		/// <summary>
		/// PBEWithHmacSHA
		/// </summary>
		public class PBEWithMacKeyFactory : PBESecretKeyFactory
		{
			public PBEWithMacKeyFactory() : base("PBEwithHmacSHA256", null, false, PKCS12, SHA256, 256, 0)
			{
			}
		}

		/// <summary>
		/// HMACSHA256
		/// </summary>
		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACSHA256", 256, new CipherKeyGenerator())
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(SHA256).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.SHA-256", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest.SHA256", "SHA-256");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + NISTObjectIdentifiers_Fields.id_sha256, "SHA-256");

				provider.addAlgorithm("SecretKeyFactory.PBEWITHHMACSHA256", PREFIX + "$PBEWithMacKeyFactory");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHHMACSHA-256", "PBEWITHHMACSHA256");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory." + NISTObjectIdentifiers_Fields.id_sha256, "PBEWITHHMACSHA256");

				provider.addAlgorithm("Mac.PBEWITHHMACSHA256", PREFIX + "$HashMac");

				addHMACAlgorithm(provider, "SHA256", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
				addHMACAlias(provider, "SHA256", PKCSObjectIdentifiers_Fields.id_hmacWithSHA256);
				addHMACAlias(provider, "SHA256", NISTObjectIdentifiers_Fields.id_sha256);
			}
		}
	}

}