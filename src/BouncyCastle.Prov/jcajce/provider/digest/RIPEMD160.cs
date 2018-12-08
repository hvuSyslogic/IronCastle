using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.iana;

namespace org.bouncycastle.jcajce.provider.digest
{
	using IANAObjectIdentifiers = org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using RIPEMD160Digest = org.bouncycastle.crypto.digests.RIPEMD160Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using PBESecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;

	public class RIPEMD160
	{
		private RIPEMD160()
		{

		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new RIPEMD160Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new RIPEMD160Digest((RIPEMD160Digest)digest);

				return d;
			}
		}

		/// <summary>
		/// RIPEMD160 HMac
		/// </summary>
		public class HashMac : BaseMac
		{
			public HashMac() : base(new HMac(new RIPEMD160Digest()))
			{
			}
		}

		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("HMACRIPEMD160", 160, new CipherKeyGenerator())
			{
			}
		}


		//
		// PKCS12 states that the same algorithm should be used
		// for the key generation as is used in the HMAC, so that
		// is what we do here.
		//

		/// <summary>
		/// PBEWithHmacRIPEMD160
		/// </summary>
		public class PBEWithHmac : BaseMac
		{
			public PBEWithHmac() : base(new HMac(new RIPEMD160Digest()), PKCS12, RIPEMD160, 160)
			{
			}
		}

		/// <summary>
		/// PBEWithHmacRIPEMD160
		/// </summary>
		public class PBEWithHmacKeyFactory : PBESecretKeyFactory
		{
			public PBEWithHmacKeyFactory() : base("PBEwithHmacRIPEMD160", null, false, PKCS12, RIPEMD160, 160, 0)
			{
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(RIPEMD160).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.RIPEMD160", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest." + TeleTrusTObjectIdentifiers_Fields.ripemd160, "RIPEMD160");

				addHMACAlgorithm(provider, "RIPEMD160", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
				addHMACAlias(provider, "RIPEMD160", IANAObjectIdentifiers_Fields.hmacRIPEMD160);


				provider.addAlgorithm("SecretKeyFactory.PBEWITHHMACRIPEMD160", PREFIX + "$PBEWithHmacKeyFactory");
				provider.addAlgorithm("Mac.PBEWITHHMACRIPEMD160", PREFIX + "$PBEWithHmac");
			}
		}
	}

}