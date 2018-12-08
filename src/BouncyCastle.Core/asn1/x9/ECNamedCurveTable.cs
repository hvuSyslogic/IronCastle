using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x9
{

	using ANSSINamedCurves = org.bouncycastle.asn1.anssi.ANSSINamedCurves;
	using ECGOST3410NamedCurves = org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
	using GMNamedCurves = org.bouncycastle.asn1.gm.GMNamedCurves;
	using NISTNamedCurves = org.bouncycastle.asn1.nist.NISTNamedCurves;
	using SECNamedCurves = org.bouncycastle.asn1.sec.SECNamedCurves;
	using TeleTrusTNamedCurves = org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;

	/// <summary>
	/// A general class that reads all X9.62 style EC curve tables.
	/// </summary>
	public class ECNamedCurveTable
	{
		/// <summary>
		/// return a X9ECParameters object representing the passed in named
		/// curve. The routine returns null if the curve is not present.
		/// </summary>
		/// <param name="name"> the name of the curve requested </param>
		/// <returns> an X9ECParameters object or null if the curve is not available. </returns>
		public static X9ECParameters getByName(string name)
		{
			X9ECParameters ecP = X962NamedCurves.getByName(name);

			if (ecP == null)
			{
				ecP = SECNamedCurves.getByName(name);
			}

			if (ecP == null)
			{
				ecP = NISTNamedCurves.getByName(name);
			}

			if (ecP == null)
			{
				ecP = TeleTrusTNamedCurves.getByName(name);
			}

			if (ecP == null)
			{
				ecP = ANSSINamedCurves.getByName(name);
			}

			if (ecP == null)
			{
				ecP = fromDomainParameters(ECGOST3410NamedCurves.getByName(name));
			}

			if (ecP == null)
			{
				ecP = GMNamedCurves.getByName(name);
			}

			return ecP;
		}

		/// <summary>
		/// return the object identifier signified by the passed in name. Null
		/// if there is no object identifier associated with name.
		/// </summary>
		/// <returns> the object identifier associated with name, if present. </returns>
		public static ASN1ObjectIdentifier getOID(string name)
		{
			ASN1ObjectIdentifier oid = X962NamedCurves.getOID(name);

			if (oid == null)
			{
				oid = SECNamedCurves.getOID(name);
			}

			if (oid == null)
			{
				oid = NISTNamedCurves.getOID(name);
			}

			if (oid == null)
			{
				oid = TeleTrusTNamedCurves.getOID(name);
			}

			if (oid == null)
			{
				oid = ANSSINamedCurves.getOID(name);
			}

			if (oid == null)
			{
				oid = ECGOST3410NamedCurves.getOID(name);
			}

			if (oid == null)
			{
				oid = GMNamedCurves.getOID(name);
			}

			return oid;
		}

		/// <summary>
		/// return a X9ECParameters object representing the passed in named
		/// curve.
		/// </summary>
		/// <param name="oid"> the object id of the curve requested </param>
		/// <returns> a standard name for the curve. </returns>
		public static string getName(ASN1ObjectIdentifier oid)
		{
			string name = X962NamedCurves.getName(oid);

			if (string.ReferenceEquals(name, null))
			{
				name = SECNamedCurves.getName(oid);
			}

			if (string.ReferenceEquals(name, null))
			{
				name = NISTNamedCurves.getName(oid);
			}

			if (string.ReferenceEquals(name, null))
			{
				name = TeleTrusTNamedCurves.getName(oid);
			}

			if (string.ReferenceEquals(name, null))
			{
				name = ANSSINamedCurves.getName(oid);
			}

			if (string.ReferenceEquals(name, null))
			{
				name = ECGOST3410NamedCurves.getName(oid);
			}

			if (string.ReferenceEquals(name, null))
			{
				name = GMNamedCurves.getName(oid);
			}

			return name;
		}

		/// <summary>
		/// return a X9ECParameters object representing the passed in named
		/// curve.
		/// </summary>
		/// <param name="oid"> the object id of the curve requested </param>
		/// <returns> an X9ECParameters object or null if the curve is not available. </returns>
		public static X9ECParameters getByOID(ASN1ObjectIdentifier oid)
		{
			X9ECParameters ecP = X962NamedCurves.getByOID(oid);

			if (ecP == null)
			{
				ecP = SECNamedCurves.getByOID(oid);
			}

			// NOTE: All the NIST curves are currently from SEC, so no point in redundant OID lookup

			if (ecP == null)
			{
				ecP = TeleTrusTNamedCurves.getByOID(oid);
			}

			if (ecP == null)
			{
				ecP = ANSSINamedCurves.getByOID(oid);
			}

			if (ecP == null)
			{
				ecP = fromDomainParameters(ECGOST3410NamedCurves.getByOID(oid));
			}

			if (ecP == null)
			{
				ecP = GMNamedCurves.getByOID(oid);
			}

			return ecP;
		}

		/// <summary>
		/// return an enumeration of the names of the available curves.
		/// </summary>
		/// <returns> an enumeration of the names of the available curves. </returns>
		public static Enumeration getNames()
		{
			Vector v = new Vector();

			addEnumeration(v, X962NamedCurves.getNames());
			addEnumeration(v, SECNamedCurves.getNames());
			addEnumeration(v, NISTNamedCurves.getNames());
			addEnumeration(v, TeleTrusTNamedCurves.getNames());
			addEnumeration(v, ANSSINamedCurves.getNames());
			addEnumeration(v, ECGOST3410NamedCurves.getNames());
			addEnumeration(v, GMNamedCurves.getNames());

			return v.elements();
		}

		private static void addEnumeration(Vector v, Enumeration e)
		{
			while (e.hasMoreElements())
			{
				v.addElement(e.nextElement());
			}
		}

		private static X9ECParameters fromDomainParameters(ECDomainParameters dp)
		{
			return dp == null ? null : new X9ECParameters(dp.getCurve(), dp.getG(), dp.getN(), dp.getH(), dp.getSeed());
		}
	}

}