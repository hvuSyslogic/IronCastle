using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.gm;

namespace org.bouncycastle.tsp
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using GMObjectIdentifiers = org.bouncycastle.asn1.gm.GMObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;

	/// <summary>
	/// Recognised hash algorithms for the time stamp protocol.
	/// </summary>
	public interface TSPAlgorithms
	{
	}

	public static class TSPAlgorithms_Fields
	{
		public static readonly ASN1ObjectIdentifier MD5 = PKCSObjectIdentifiers_Fields.md5;
		public static readonly ASN1ObjectIdentifier SHA1 = OIWObjectIdentifiers_Fields.idSHA1;
		public static readonly ASN1ObjectIdentifier SHA224 = NISTObjectIdentifiers_Fields.id_sha224;
		public static readonly ASN1ObjectIdentifier SHA256 = NISTObjectIdentifiers_Fields.id_sha256;
		public static readonly ASN1ObjectIdentifier SHA384 = NISTObjectIdentifiers_Fields.id_sha384;
		public static readonly ASN1ObjectIdentifier SHA512 = NISTObjectIdentifiers_Fields.id_sha512;
		public static readonly ASN1ObjectIdentifier RIPEMD128 = TeleTrusTObjectIdentifiers_Fields.ripemd128;
		public static readonly ASN1ObjectIdentifier RIPEMD160 = TeleTrusTObjectIdentifiers_Fields.ripemd160;
		public static readonly ASN1ObjectIdentifier RIPEMD256 = TeleTrusTObjectIdentifiers_Fields.ripemd256;
		public static readonly ASN1ObjectIdentifier GOST3411 = CryptoProObjectIdentifiers_Fields.gostR3411;
		public static readonly ASN1ObjectIdentifier GOST3411_2012_256 = RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256;
		public static readonly ASN1ObjectIdentifier GOST3411_2012_512 = RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512;
		public static readonly ASN1ObjectIdentifier SM3 = GMObjectIdentifiers_Fields.sm3;
		public static readonly Set ALLOWED = new HashSet(Arrays.asList(new ASN1ObjectIdentifier[] {SM3, GOST3411, GOST3411_2012_256, GOST3411_2012_512, MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD128, RIPEMD160, RIPEMD256}));
	}

}