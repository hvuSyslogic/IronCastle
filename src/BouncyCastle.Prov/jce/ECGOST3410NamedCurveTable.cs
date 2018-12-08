namespace org.bouncycastle.jce
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ECGOST3410NamedCurves = org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECNamedCurveParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

	/// <summary>
	/// a table of locally supported named curves.
	/// </summary>
	public class ECGOST3410NamedCurveTable
	{
		/// <summary>
		/// return a parameter spec representing the passed in named
		/// curve. The routine returns null if the curve is not present.
		/// </summary>
		/// <param name="name"> the name of the curve requested </param>
		/// <returns> a parameter spec for the curve, null if it is not available. </returns>
		public static ECNamedCurveParameterSpec getParameterSpec(string name)
		{
			ECDomainParameters ecP = ECGOST3410NamedCurves.getByName(name);
			if (ecP == null)
			{
				try
				{
					ecP = ECGOST3410NamedCurves.getByOID(new ASN1ObjectIdentifier(name));
				}
				catch (IllegalArgumentException)
				{
					return null; // not an oid.
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
			return ECGOST3410NamedCurves.getNames();
		}
	}

}