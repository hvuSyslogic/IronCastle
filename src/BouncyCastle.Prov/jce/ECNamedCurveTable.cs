using org.bouncycastle.crypto.ec;
using org.bouncycastle.asn1.x9;

namespace org.bouncycastle.jce
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using ECNamedCurveParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

	/// <summary>
	/// a table of locally supported named curves.
	/// </summary>
	public class ECNamedCurveTable
	{
		/// <summary>
		/// return a parameter spec representing the passed in named
		/// curve. The routine returns null if the curve is not present.
		/// </summary>
		/// <param name="name"> the name of the curve requested </param>
		/// <returns> a parameter spec for the curve, null if it is not available. </returns>
		public static ECNamedCurveParameterSpec getParameterSpec(string name)
		{
			X9ECParameters ecP = CustomNamedCurves.getByName(name);
			if (ecP == null)
			{
				try
				{
					ecP = CustomNamedCurves.getByOID(new ASN1ObjectIdentifier(name));
				}
				catch (IllegalArgumentException)
				{
					// ignore - not an oid
				}

				if (ecP == null)
				{
					ecP = ECNamedCurveTable.getByName(name);
					if (ecP == null)
					{
						try
						{
							ecP = ECNamedCurveTable.getByOID(new ASN1ObjectIdentifier(name));
						}
						catch (IllegalArgumentException)
						{
							// ignore - not an oid
						}
					}
				}
			}

			if (ecP == null)
			{
				return null;
			}

			return new ECNamedCurveParameterSpec(name, ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
		}

		/// <summary>
		/// return an enumeration of the names of the available curves.
		/// </summary>
		/// <returns> an enumeration of the names of the available curves. </returns>
		public static Enumeration getNames()
		{
			return ECNamedCurveTable.getNames();
		}
	}

}