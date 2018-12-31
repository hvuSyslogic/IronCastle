using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.math.ec;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;
using org.bouncycastle.util.encoders;

namespace org.bouncycastle.asn1.gm
{

						
	/// <summary>
	/// Chinese standard GM named curves.
	/// </summary>
	public class GMNamedCurves
	{
		private static ECCurve configureCurve(ECCurve curve)
		{
			return curve;
		}

		private static BigInteger fromHex(string hex)
		{
			return new BigInteger(1, Hex.decode(hex));
		}

		/*
		 * SM2SysParams
		 */
		internal static X9ECParametersHolder sm2p256v1 = new X9ECParametersHolderAnonymousInnerClass();

		public class X9ECParametersHolderAnonymousInnerClass : X9ECParametersHolder
		{
			public override X9ECParameters createParameters()
			{

				BigInteger p = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
				BigInteger a = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
				BigInteger b = fromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
				byte[] S = null;
				BigInteger n = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
				BigInteger h = BigInteger.valueOf(1);

				ECCurve curve = configureCurve(new ECCurve.Fp(p, a, b, n, h));
				X9ECPoint G = new X9ECPoint(curve, Hex.decode("04" + "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7" + "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"));

				return new X9ECParameters(curve, G, n, h, S);
			}
		}

		internal static X9ECParametersHolder wapip192v1 = new X9ECParametersHolderAnonymousInnerClass2();

		public class X9ECParametersHolderAnonymousInnerClass2 : X9ECParametersHolder
		{
			public override X9ECParameters createParameters()
			{
				BigInteger p = fromHex("BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F");
				BigInteger a = fromHex("BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985");
				BigInteger b = fromHex("1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1");
				byte[] S = null;
				BigInteger n = fromHex("BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677");
				BigInteger h = BigInteger.valueOf(1);

				ECCurve curve = configureCurve(new ECCurve.Fp(p, a, b, n, h));
				X9ECPoint G = new X9ECPoint(curve, Hex.decode("04" + "4AD5F7048DE709AD51236DE6" + "5E4D4B482C836DC6E4106640" + "02BB3A02D4AAADACAE24817A" + "4CA3A1B014B5270432DB27D2"));

				return new X9ECParameters(curve, G, n, h, S);
			}
		}

		internal static readonly Hashtable objIds = new Hashtable();
		internal static readonly Hashtable curves = new Hashtable();
		internal static readonly Hashtable names = new Hashtable();

		internal static void defineCurve(string name, ASN1ObjectIdentifier oid, X9ECParametersHolder holder)
		{
			objIds.put(Strings.toLowerCase(name), oid);
			names.put(oid, name);
			curves.put(oid, holder);
		}

		static GMNamedCurves()
		{
			defineCurve("wapip192v1", GMObjectIdentifiers_Fields.wapip192v1, wapip192v1);
			defineCurve("sm2p256v1", GMObjectIdentifiers_Fields.sm2p256v1, sm2p256v1);
		}

		public static X9ECParameters getByName(string name)
		{
			ASN1ObjectIdentifier oid = getOID(name);
			return oid == null ? null : getByOID(oid);
		}

		/// <summary>
		/// return the X9ECParameters object for the named curve represented by
		/// the passed in object identifier. Null if the curve isn't present.
		/// </summary>
		/// <param name="oid"> an object identifier representing a named curve, if present. </param>
		public static X9ECParameters getByOID(ASN1ObjectIdentifier oid)
		{
			X9ECParametersHolder holder = (X9ECParametersHolder)curves.get(oid);
			return holder == null ? null : holder.getParameters();
		}

		/// <summary>
		/// return the object identifier signified by the passed in name. Null
		/// if there is no object identifier associated with name.
		/// </summary>
		/// <returns> the object identifier associated with name, if present. </returns>
		public static ASN1ObjectIdentifier getOID(string name)
		{
			return (ASN1ObjectIdentifier)objIds.get(Strings.toLowerCase(name));
		}

		/// <summary>
		/// return the named curve name represented by the given object identifier.
		/// </summary>
		public static string getName(ASN1ObjectIdentifier oid)
		{
			return (string)names.get(oid);
		}

		/// <summary>
		/// returns an enumeration containing the name strings for curves
		/// contained in this structure.
		/// </summary>
		public static Enumeration getNames()
		{
			return names.elements();
		}
	}


}