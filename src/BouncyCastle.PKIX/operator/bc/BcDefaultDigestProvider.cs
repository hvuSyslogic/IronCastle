using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.teletrust;

namespace org.bouncycastle.@operator.bc
{

	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using ExtendedDigest = org.bouncycastle.crypto.ExtendedDigest;
	using org.bouncycastle.crypto.digests;

	public class BcDefaultDigestProvider : BcDigestProvider
	{
		private static readonly Map lookup = createTable();

		private static Map createTable()
		{
			Map table = new HashMap();

			table.put(OIWObjectIdentifiers_Fields.idSHA1, new BcDigestProviderAnonymousInnerClass());
			table.put(NISTObjectIdentifiers_Fields.id_sha224, new BcDigestProviderAnonymousInnerClass2());
			table.put(NISTObjectIdentifiers_Fields.id_sha256, new BcDigestProviderAnonymousInnerClass3());
			table.put(NISTObjectIdentifiers_Fields.id_sha384, new BcDigestProviderAnonymousInnerClass4());
			table.put(NISTObjectIdentifiers_Fields.id_sha512, new BcDigestProviderAnonymousInnerClass5());
			table.put(NISTObjectIdentifiers_Fields.id_sha3_224, new BcDigestProviderAnonymousInnerClass6());
			table.put(NISTObjectIdentifiers_Fields.id_sha3_256, new BcDigestProviderAnonymousInnerClass7());
			table.put(NISTObjectIdentifiers_Fields.id_sha3_384, new BcDigestProviderAnonymousInnerClass8());
			table.put(NISTObjectIdentifiers_Fields.id_sha3_512, new BcDigestProviderAnonymousInnerClass9());
			table.put(PKCSObjectIdentifiers_Fields.md5, new BcDigestProviderAnonymousInnerClass10());
			table.put(PKCSObjectIdentifiers_Fields.md4, new BcDigestProviderAnonymousInnerClass11());
			table.put(PKCSObjectIdentifiers_Fields.md2, new BcDigestProviderAnonymousInnerClass12());
			table.put(CryptoProObjectIdentifiers_Fields.gostR3411, new BcDigestProviderAnonymousInnerClass13());
			table.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256, new BcDigestProviderAnonymousInnerClass14());
			table.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512, new BcDigestProviderAnonymousInnerClass15());
			table.put(TeleTrusTObjectIdentifiers_Fields.ripemd128, new BcDigestProviderAnonymousInnerClass16());
			table.put(TeleTrusTObjectIdentifiers_Fields.ripemd160, new BcDigestProviderAnonymousInnerClass17());
			table.put(TeleTrusTObjectIdentifiers_Fields.ripemd256, new BcDigestProviderAnonymousInnerClass18());

			return Collections.unmodifiableMap(table);
		}

		public class BcDigestProviderAnonymousInnerClass : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new SHA1Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass2 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new SHA224Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass3 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new SHA256Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass4 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new SHA384Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass5 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new SHA512Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass6 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new SHA3Digest(224);
			}
		}

		public class BcDigestProviderAnonymousInnerClass7 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new SHA3Digest(256);
			}
		}

		public class BcDigestProviderAnonymousInnerClass8 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new SHA3Digest(384);
			}
		}

		public class BcDigestProviderAnonymousInnerClass9 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new SHA3Digest(512);
			}
		}

		public class BcDigestProviderAnonymousInnerClass10 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new MD5Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass11 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new MD4Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass12 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new MD2Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass13 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new GOST3411Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass14 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new GOST3411_2012_256Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass15 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new GOST3411_2012_512Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass16 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new RIPEMD128Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass17 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new RIPEMD160Digest();
			}
		}

		public class BcDigestProviderAnonymousInnerClass18 : BcDigestProvider
		{
			public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return new RIPEMD256Digest();
			}
		}

		public static readonly BcDigestProvider INSTANCE = new BcDefaultDigestProvider();

		private BcDefaultDigestProvider()
		{

		}

		public virtual ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
		{
			BcDigestProvider extProv = (BcDigestProvider)lookup.get(digestAlgorithmIdentifier.getAlgorithm());

			if (extProv == null)
			{
				throw new OperatorCreationException("cannot recognise digest");
			}

			return extProv.get(digestAlgorithmIdentifier);
		}
	}

}