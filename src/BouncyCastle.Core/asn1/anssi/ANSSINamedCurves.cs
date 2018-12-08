using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.anssi
{

	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ECParametersHolder = org.bouncycastle.asn1.x9.X9ECParametersHolder;
	using X9ECPoint = org.bouncycastle.asn1.x9.X9ECPoint;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// ANSSI Elliptic curve table.
	/// </summary>
	public class ANSSINamedCurves
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
		 * FRP256v1
		 */
		internal static X9ECParametersHolder FRP256v1 = new X9ECParametersHolderAnonymousInnerClass();

		public class X9ECParametersHolderAnonymousInnerClass : X9ECParametersHolder
		{
			public override X9ECParameters createParameters()
			{
				BigInteger p = fromHex("F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03");
				BigInteger a = fromHex("F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00");
				BigInteger b = fromHex("EE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F");
				byte[] S = null;
				BigInteger n = fromHex("F1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1");
				BigInteger h = BigInteger.valueOf(1);

				ECCurve curve = configureCurve(new ECCurve.Fp(p, a, b, n, h));
				X9ECPoint G = new X9ECPoint(curve, Hex.decode("04" + "B6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF" + "6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB"));

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

		static ANSSINamedCurves()
		{
			defineCurve("FRP256v1", ANSSIObjectIdentifiers_Fields.FRP256v1, FRP256v1);
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