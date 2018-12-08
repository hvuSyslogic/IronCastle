using org.bouncycastle.asn1.edec;

using System;

namespace org.bouncycastle.jcajce.spec
{

	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;

	/// <summary>
	/// ParameterSpec for XDH key agreement algorithms.
	/// </summary>
	public class XDHParameterSpec : AlgorithmParameterSpec
	{
		public const string X25519 = "X25519";
		public const string X448 = "X448";

		private readonly string curveName;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="curveName"> name of the curve to specify. </param>
		public XDHParameterSpec(string curveName)
		{
			if (curveName.Equals(X25519, StringComparison.OrdinalIgnoreCase))
			{
				this.curveName = X25519;
			}
			else if (curveName.Equals(X448, StringComparison.OrdinalIgnoreCase))
			{
				this.curveName = X448;
			}
			else if (curveName.Equals(EdECObjectIdentifiers_Fields.id_X25519.getId()))
			{
				this.curveName = X25519;
			}
			else if (curveName.Equals(EdECObjectIdentifiers_Fields.id_X448.getId()))
			{
				this.curveName = X448;
			}
			else
			{
				throw new IllegalArgumentException("unrecognized curve name: " + curveName);
			}
		}

		/// <summary>
		/// Return the curve name specified by this parameterSpec.
		/// </summary>
		/// <returns> the name of the curve this parameterSpec specifies. </returns>
		public virtual string getCurveName()
		{
			return curveName;
		}
	}

}