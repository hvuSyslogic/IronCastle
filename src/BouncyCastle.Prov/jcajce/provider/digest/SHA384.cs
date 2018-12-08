using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jcajce.provider.digest
{
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using SHA384Digest = org.bouncycastle.crypto.digests.SHA384Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using OldHMac = org.bouncycastle.crypto.macs.OldHMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

	public class SHA384
	{
		private SHA384()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new SHA384Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new SHA384Digest((SHA384Digest)digest);

				return d;
			}
		}

		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new SHA384Digest()))
			{
			}
		}

		/// <summary>
		/// HMACSHA384
		/// </summary>
		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACSHA384", 384, new CipherKeyGenerator())
			{
			}
		}

		public class OldSHA384 : BaseMac
		{
			public OldSHA384() : base(new OldHMac(new SHA384Digest()))
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(SHA384).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.SHA-384", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest.SHA384", "SHA-384");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + NISTObjectIdentifiers_Fields.id_sha384, "SHA-384");
				provider.addAlgorithm("Mac.OLDHMACSHA384", PREFIX + "$OldSHA384");

				provider.addAlgorithm("Mac.PBEWITHHMACSHA384", PREFIX + "$HashMac");

				addHMACAlgorithm(provider, "SHA384", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
				addHMACAlias(provider, "SHA384", PKCSObjectIdentifiers_Fields.id_hmacWithSHA384);
			}
		}
	}

}