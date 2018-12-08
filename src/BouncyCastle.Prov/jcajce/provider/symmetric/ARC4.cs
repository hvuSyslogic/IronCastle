using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jcajce.provider.symmetric
{
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using RC4Engine = org.bouncycastle.crypto.engines.RC4Engine;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseStreamCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
	using PBESecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class ARC4
	{
		private ARC4()
		{
		}

		public class Base : BaseStreamCipher
		{
			public Base() : base(new RC4Engine(), 0)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("RC4", 128, new CipherKeyGenerator())
			{
			}
		}

		/// <summary>
		/// PBEWithSHAAnd128BitRC4
		/// </summary>
		public class PBEWithSHAAnd128BitKeyFactory : PBESecretKeyFactory
		{
			public PBEWithSHAAnd128BitKeyFactory() : base("PBEWithSHAAnd128BitRC4", org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC4, true, PKCS12, SHA1, 128, 0)
			{
			}
		}

		/// <summary>
		/// PBEWithSHAAnd40BitRC4
		/// </summary>
		public class PBEWithSHAAnd40BitKeyFactory : PBESecretKeyFactory
		{
			public PBEWithSHAAnd40BitKeyFactory() : base("PBEWithSHAAnd128BitRC4", org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC4, true, PKCS12, SHA1, 40, 0)
			{
			}
		}


		/// <summary>
		/// PBEWithSHAAnd128BitRC4
		/// </summary>
		public class PBEWithSHAAnd128Bit : BaseStreamCipher
		{
			public PBEWithSHAAnd128Bit() : base(new RC4Engine(), 0, 128, SHA1)
			{
			}
		}

		/// <summary>
		/// PBEWithSHAAnd40BitRC4
		/// </summary>
		public class PBEWithSHAAnd40Bit : BaseStreamCipher
		{
			public PBEWithSHAAnd40Bit() : base(new RC4Engine(), 0, 40, SHA1)
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(ARC4).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Cipher.ARC4", PREFIX + "$Base");
				provider.addAlgorithm("Alg.Alias.Cipher", PKCSObjectIdentifiers_Fields.rc4, "ARC4");
				provider.addAlgorithm("Alg.Alias.Cipher.ARCFOUR", "ARC4");
				provider.addAlgorithm("Alg.Alias.Cipher.RC4", "ARC4");
				provider.addAlgorithm("KeyGenerator.ARC4", PREFIX + "$KeyGen");
				provider.addAlgorithm("Alg.Alias.KeyGenerator.RC4", "ARC4");
				provider.addAlgorithm("Alg.Alias.KeyGenerator.1.2.840.113549.3.4", "ARC4");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHAAND128BITRC4", PREFIX + "$PBEWithSHAAnd128BitKeyFactory");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHAAND40BITRC4", PREFIX + "$PBEWithSHAAnd40BitKeyFactory");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC4, "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC4, "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND40BITRC4", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND128BITRC4", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDRC4", "PKCS12PBE");
				provider.addAlgorithm("Cipher.PBEWITHSHAAND128BITRC4", PREFIX + "$PBEWithSHAAnd128Bit");
				provider.addAlgorithm("Cipher.PBEWITHSHAAND40BITRC4", PREFIX + "$PBEWithSHAAnd40Bit");

				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC4, "PBEWITHSHAAND128BITRC4");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC4, "PBEWITHSHAAND40BITRC4");

				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND128BITRC4", "PBEWITHSHAAND128BITRC4");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND40BITRC4", "PBEWITHSHAAND40BITRC4");

				provider.addAlgorithm("Alg.Alias.Cipher", PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC4, "PBEWITHSHAAND128BITRC4");
				provider.addAlgorithm("Alg.Alias.Cipher", PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC4, "PBEWITHSHAAND40BITRC4");
			}
		}
	}

}