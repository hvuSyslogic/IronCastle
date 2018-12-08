using org.bouncycastle.asn1.gm;

namespace org.bouncycastle.jcajce.provider.digest
{
	using GMObjectIdentifiers = org.bouncycastle.asn1.gm.GMObjectIdentifiers;
	using SM3Digest = org.bouncycastle.crypto.digests.SM3Digest;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

	public class SM3
	{
		private SM3()
		{
		}

		public class Digest : BCMessageDigest, Cloneable
		{
			public Digest() : base(new SM3Digest())
			{
			}

			public virtual object clone()
			{
				Digest d = (Digest)base.clone();
				d.digest = new SM3Digest((SM3Digest)digest);

				return d;
			}
		}

		public class Mappings : DigestAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(SM3).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("MessageDigest.SM3", PREFIX + "$Digest");
				provider.addAlgorithm("Alg.Alias.MessageDigest.SM3", "SM3");
				provider.addAlgorithm("Alg.Alias.MessageDigest.1.2.156.197.1.401", "SM3"); // old draft OID - deprecated
				provider.addAlgorithm("Alg.Alias.MessageDigest." + GMObjectIdentifiers_Fields.sm3, "SM3");
			}
		}
	}

}